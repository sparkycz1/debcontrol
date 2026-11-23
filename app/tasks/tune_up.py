"""The task behind a tune-up ("Komplet") — see `app.services.tune_up` for
the steps and why they run in this order.

`_run_tune_up` follows one `TuneUpRun` through its steps. A step that runs
inside debcontrol (refreshing facts, a monitoring sample, the image check)
is awaited here directly; one that is a job of its own (the update run,
Docker jobs, the security audit) is started through the same code its own
button uses and then waited for, its id kept in the step's `ref`. So when
the task stops half way — a worker restart, or the update of debcontrol's
own host — `reconcile_tune_up_runs` hands the run to a new task, which
skips finished steps and waits for the one under way instead of starting
it again.

Tests call the underscore-prefixed coroutines directly.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update

from app.core.app_settings import get_or_create_app_settings
from app.db import session as db_session
from app.db.models import tune_up as model
from app.db.models.docker import DockerJob, DockerJobKind, DockerJobStatus
from app.db.models.machine import Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.security_audit import SecurityAudit, SecurityAuditStatus
from app.db.models.tune_up import TuneUpRun
from app.services import docker_actions, docker_jobs, machine_health, tune_up
from app.ssh.docker_prune import PruneOptions
from app.tasks import jobs
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# How often a waiting step looks at what it waits for (and writes the
# run's heartbeat).
POLL_SECONDS = 10.0
HEARTBEAT_SECONDS = 60.0
# Longest wait for one job-backed step before it counts as failed (the
# job itself carries on and stays in its own history).
DOCKER_WAIT = timedelta(hours=2)
AUDIT_WAIT = timedelta(hours=1)
# The whole run, as Celery's hard limit: every step at its longest.
TASK_TIME_LIMIT_SECONDS = 9 * 60 * 60

# `docker system prune -a` without volumes (Jakub's choice, 0.146.0).
PRUNE = PruneOptions(containers=True, images=True, all_images=True, networks=True, build_cache=True)

_DOCKER_FINAL = {
    DockerJobStatus.SUCCEEDED,
    DockerJobStatus.FAILED,
    DockerJobStatus.BLOCKED,
    DockerJobStatus.SKIPPED,
    DockerJobStatus.CANCELLED,
}

Detail = dict[str, Any]
StepResult = tuple[str, Detail | None]


@dataclass
class _Ctx:
    run_id: uuid.UUID
    machine_id: uuid.UUID
    options: tune_up.Options
    started_by: str
    held: bool

    @property
    def mid(self) -> str:
        return str(self.machine_id)


def _error(result: dict[str, Any] | None, fallback: str = "Unknown error.") -> Detail:
    return {"error": str((result or {}).get("error") or fallback)[:500]}


async def _heartbeat(run_id: uuid.UUID) -> None:
    async with db_session.AsyncSessionLocal() as db:
        await db.execute(
            update(TuneUpRun)
            .where(TuneUpRun.id == run_id)
            .values(heartbeat_at=datetime.now(UTC))
            .execution_options(synchronize_session=False)
        )
        await db.commit()


async def _save_step(run_id: uuid.UUID, index: int, **changes: Any) -> None:
    """Write one step's changes (and the heartbeat)."""
    async with db_session.AsyncSessionLocal() as db:
        run = await db.get(TuneUpRun, run_id)
        if run is None:
            return
        steps = [dict(step) for step in run.steps or []]
        if index < len(steps):
            ref = dict(steps[index].get("ref") or {})
            ref.update(changes.pop("ref", {}) or {})
            steps[index].update(changes, ref=ref)
        run.steps = steps
        run.heartbeat_at = datetime.now(UTC)
        await db.commit()


async def _beat_forever(run_id: uuid.UUID) -> None:
    """Keep the heartbeat fresh while a step is awaited here (an update
    followed for an hour must not look like a stopped task)."""
    while True:
        await asyncio.sleep(HEARTBEAT_SECONDS)
        try:
            await _heartbeat(run_id)
        except Exception:  # a missed beat is retried on the next one
            logger.warning("Tune-up heartbeat failed for %s", run_id, exc_info=True)


async def _wait(run_id: uuid.UUID, done: Callable[[], Awaitable[bool]], limit: timedelta) -> bool:
    """Poll `done` until it says yes or `limit` passes; True when done."""
    deadline = datetime.now(UTC) + limit
    while True:
        if await done():
            return True
        if datetime.now(UTC) >= deadline:
            return False
        await _heartbeat(run_id)
        await asyncio.sleep(POLL_SECONDS)


async def _machine(machine_id: uuid.UUID) -> Machine | None:
    async with db_session.AsyncSessionLocal() as db:
        return await db.get(Machine, machine_id)


# --- Steps -------------------------------------------------------------------


async def _step_refresh(ctx: _Ctx, ref: dict[str, Any], index: int) -> StepResult:
    facts = await jobs._refresh_machine_facts(ctx.mid)
    if not facts.get("ok"):
        return tune_up.STEP_FAILED, _error(facts)
    others = [
        await jobs._refresh_machine_packages(ctx.mid),
        await jobs._refresh_machine_services(ctx.mid),
        await jobs._check_machine_readiness(ctx.mid),
    ]
    failed = next((r for r in others if not r.get("ok")), None)
    return (tune_up.STEP_FAILED, _error(failed)) if failed else (tune_up.STEP_OK, None)


async def _step_system_update(ctx: _Ctx, ref: dict[str, Any], index: int) -> StepResult:
    run_id = ref.get("update_run_id")
    if not run_id:
        async with db_session.AsyncSessionLocal() as db:
            update_run = MachineUpdateRun(
                machine_id=ctx.machine_id,
                strategy=UpgradeStrategy.FULL_UPGRADE,
                snapshot_before=ctx.options.snapshot,
            )
            db.add(update_run)
            await db.commit()
            run_id = str(update_run.id)
        await _save_step(ctx.run_id, index, ref={"update_run_id": run_id})
        # A _TryLaterError: still running on the machine; waited for below.
        with contextlib.suppress(jobs._TryLaterError):
            await jobs._run_machine_update(run_id)
    async with db_session.AsyncSessionLocal() as db:
        limit = (await get_or_create_app_settings(db)).update_timeout_seconds

    async def finished() -> bool:
        async with db_session.AsyncSessionLocal() as db:
            status = await db.scalar(
                select(MachineUpdateRun.status).where(MachineUpdateRun.id == uuid.UUID(run_id))
            )
        return status in (UpdateRunStatus.SUCCEEDED, UpdateRunStatus.FAILED, None)

    if not await _wait(ctx.run_id, finished, timedelta(seconds=limit + 1800)):
        return tune_up.STEP_FAILED, {"code": "timed_out"}
    async with db_session.AsyncSessionLocal() as db:
        ended = await db.get(MachineUpdateRun, uuid.UUID(run_id))
    if ended is None:
        return tune_up.STEP_FAILED, {"error": "The update run was removed."}
    if ended.status == UpdateRunStatus.SUCCEEDED:
        return tune_up.STEP_OK, {"code": "updated", "run_id": run_id}
    return tune_up.STEP_FAILED, {"error": ended.error or "The update failed.", "run_id": run_id}


async def _has_docker(ctx: _Ctx) -> bool:
    machine = await _machine(ctx.machine_id)
    return machine is not None and machine.docker_status == "ok"


async def _step_image_check(ctx: _Ctx, ref: dict[str, Any], index: int) -> StepResult:
    if not await _has_docker(ctx):
        return tune_up.STEP_SKIPPED, {"code": "no_docker"}
    result = await jobs._check_machine_image_updates(ctx.mid)
    if not result.get("ok"):
        return tune_up.STEP_FAILED, _error(result)
    return tune_up.STEP_OK, {"code": "image_updates", "count": int(result.get("updates") or 0)}


async def _wait_for_jobs(ctx: _Ctx, job_ids: list[str]) -> list[DockerJob] | None:
    """Wait for Docker jobs; None when they did not finish in time."""
    ids = [uuid.UUID(j) for j in job_ids]

    async def finished() -> bool:
        async with db_session.AsyncSessionLocal() as db:
            statuses = (
                await db.execute(select(DockerJob.status).where(DockerJob.id.in_(ids)))
            ).scalars().all()
        return all(status in _DOCKER_FINAL for status in statuses)

    if not await _wait(ctx.run_id, finished, DOCKER_WAIT):
        return None
    async with db_session.AsyncSessionLocal() as db:
        return list(
            (await db.execute(select(DockerJob).where(DockerJob.id.in_(ids)))).scalars().all()
        )


async def _step_docker_update(ctx: _Ctx, ref: dict[str, Any], index: int) -> StepResult:
    if not await _has_docker(ctx):
        return tune_up.STEP_SKIPPED, {"code": "no_docker"}
    job_ids: list[str] | None = ref.get("job_ids")
    protected = int(ref.get("protected") or 0)
    if job_ids is None:
        async with db_session.AsyncSessionLocal() as db:
            machine = await db.get(Machine, ctx.machine_id)
            if machine is None:
                return tune_up.STEP_FAILED, {"error": "Machine not found."}
            names = [
                str(c["name"])
                for c in machine.docker_containers or []
                if isinstance(c, dict) and c.get("name")
            ]
            if not names:
                return tune_up.STEP_SKIPPED, {"code": "no_containers"}
            queued = await docker_actions.update_containers(
                db, machine, names, started_by=ctx.started_by
            )
        job_ids = [str(job.id) for job in queued.jobs]
        protected = sum(1 for why in queued.skipped.values() if why == "protected")
        await _save_step(ctx.run_id, index, ref={"job_ids": job_ids, "protected": protected})
    if not job_ids:
        return tune_up.STEP_SKIPPED, {"code": "no_containers"}
    finished = await _wait_for_jobs(ctx, job_ids)
    if finished is None:
        return tune_up.STEP_FAILED, {"code": "timed_out"}
    count = Counter(str(job.status) for job in finished)
    detail = {
        "code": "containers",
        "updated": count[DockerJobStatus.SUCCEEDED.value],
        "current": count[DockerJobStatus.SKIPPED.value],
        "blocked": count[DockerJobStatus.BLOCKED.value],
        "failed": count[DockerJobStatus.FAILED.value] + count[DockerJobStatus.CANCELLED.value],
        "protected": protected,
    }
    return (tune_up.STEP_FAILED if detail["failed"] else tune_up.STEP_OK), detail


async def _one_docker_job(
    ctx: _Ctx,
    ref: dict[str, Any],
    index: int,
    kind: str,
    target: str,
    queue: Callable[[Any, Machine], Awaitable[DockerJob | None]],
) -> tuple[str, DockerJob | None, Detail | None]:
    """Queue one Docker job (or take the same one already waiting) and wait
    for it. Returns (step status, the job, detail on failure)."""
    job_id = ref.get("job_id")
    if not job_id:
        async with db_session.AsyncSessionLocal() as db:
            machine = await db.get(Machine, ctx.machine_id)
            if machine is None:
                return tune_up.STEP_FAILED, None, {"error": "Machine not found."}
            job = await queue(db, machine) or await docker_jobs.active_job(
                db, machine.id, kind, target
            )
            if job is None:
                return tune_up.STEP_FAILED, None, {"error": "The job could not be queued."}
            job_id = str(job.id)
        await _save_step(ctx.run_id, index, ref={"job_id": job_id})
    finished = await _wait_for_jobs(ctx, [job_id])
    if not finished:
        return tune_up.STEP_FAILED, None, {"code": "timed_out"}
    job = finished[0]
    if job.status in (DockerJobStatus.SUCCEEDED, DockerJobStatus.SKIPPED):
        return tune_up.STEP_OK, job, None
    return tune_up.STEP_FAILED, job, {"error": (job.error or str(job.status))[:500]}


async def _step_docker_prune(ctx: _Ctx, ref: dict[str, Any], index: int) -> StepResult:
    if not await _has_docker(ctx):
        return tune_up.STEP_SKIPPED, {"code": "no_docker"}

    async def queue(db: Any, machine: Machine) -> DockerJob | None:
        return await docker_actions.prune(db, machine, PRUNE, started_by=ctx.started_by)

    status, job, detail = await _one_docker_job(
        ctx, ref, index, DockerJobKind.PRUNE, "prune", queue
    )
    if status == tune_up.STEP_OK and job is not None:
        reclaimed = (job.result or {}).get("reclaimed_bytes")
        return status, {"code": "reclaimed", "bytes": int(reclaimed or 0)}
    return status, detail


async def _step_image_scan(ctx: _Ctx, ref: dict[str, Any], index: int) -> StepResult:
    if not await _has_docker(ctx):
        return tune_up.STEP_SKIPPED, {"code": "no_docker"}

    async def queue(db: Any, machine: Machine) -> DockerJob | None:
        return await docker_actions.scan_images(
            db, machine, started_by=ctx.started_by, scope="all"
        )

    status, _job, detail = await _one_docker_job(
        ctx, ref, index, DockerJobKind.IMAGE_SCAN, "scope:all", queue
    )
    return status, detail if status != tune_up.STEP_OK else {"code": "scanned"}


async def _step_security_audit(ctx: _Ctx, ref: dict[str, Any], index: int) -> StepResult:
    audit_id = ref.get("audit_id")
    if not audit_id:
        async with db_session.AsyncSessionLocal() as db:
            active = await db.scalar(
                select(SecurityAudit.id)
                .where(
                    SecurityAudit.machine_id == ctx.machine_id,
                    SecurityAudit.status.in_(
                        (SecurityAuditStatus.PENDING, SecurityAuditStatus.RUNNING)
                    ),
                )
                .limit(1)
            )
            if active is None:
                audit = SecurityAudit(
                    machine_id=ctx.machine_id,
                    install_if_missing=True,
                    started_by=ctx.started_by,
                    created_at=datetime.now(UTC),
                )
                db.add(audit)
                await db.commit()
                audit_id = str(audit.id)
                start_it = True
            else:
                audit_id = str(active)
                start_it = False
        await _save_step(ctx.run_id, index, ref={"audit_id": audit_id})
        if start_it:
            await jobs._run_security_audit(audit_id)

    async def finished() -> bool:
        async with db_session.AsyncSessionLocal() as db:
            status = await db.scalar(
                select(SecurityAudit.status).where(SecurityAudit.id == uuid.UUID(audit_id))
            )
        return status in (SecurityAuditStatus.SUCCEEDED, SecurityAuditStatus.FAILED, None)

    if not await _wait(ctx.run_id, finished, AUDIT_WAIT):
        return tune_up.STEP_FAILED, {"code": "timed_out"}
    async with db_session.AsyncSessionLocal() as db:
        done = await db.get(SecurityAudit, uuid.UUID(audit_id))
    if done is None:
        return tune_up.STEP_FAILED, {"error": "The audit was removed."}
    if done.status != SecurityAuditStatus.SUCCEEDED:
        return tune_up.STEP_FAILED, {"error": done.error or "The audit failed."}
    return tune_up.STEP_OK, {
        "code": "audit",
        "index": done.hardening_index,
        "warnings": len(done.warnings or []),
    }


async def _step_final_refresh(ctx: _Ctx, ref: dict[str, Any], index: int) -> StepResult:
    facts = await jobs._refresh_machine_facts(ctx.mid)
    results = [
        facts,
        await jobs._refresh_machine_packages(ctx.mid),
        await jobs._check_machine_updates(ctx.mid),
        await jobs._sample_machine_monitoring(ctx.mid),
    ]
    async with db_session.AsyncSessionLocal() as db:
        machine = await db.get(Machine, ctx.machine_id)
        health = None
        if machine is not None:
            await machine_health.refresh(db, machine)
            await db.refresh(machine)
            health = machine.health_status
    failed = next((r for r in results if not r.get("ok")), None)
    if failed:
        return tune_up.STEP_FAILED, _error(failed)
    return tune_up.STEP_OK, ({"code": "health", "status": str(health)} if health else None)


async def _step_reboot(ctx: _Ctx, ref: dict[str, Any], index: int) -> StepResult:
    if ctx.held:
        return tune_up.STEP_SKIPPED, {"code": "self_host"}
    machine = await _machine(ctx.machine_id)
    if machine is None or not machine.reboot_required:
        return tune_up.STEP_SKIPPED, {"code": "not_needed"}
    result = await jobs._send_machine_power_command(ctx.mid, "reboot")
    if not result.get("ok"):
        return tune_up.STEP_FAILED, _error(result)
    return tune_up.STEP_OK, {"code": "rebooting"}


STEP_RUNNERS: dict[str, Callable[[_Ctx, dict[str, Any], int], Awaitable[StepResult]]] = {
    "refresh": _step_refresh,
    "system_update": _step_system_update,
    "image_check": _step_image_check,
    "docker_update": _step_docker_update,
    "docker_prune": _step_docker_prune,
    "image_scan": _step_image_scan,
    "security_audit": _step_security_audit,
    "final_refresh": _step_final_refresh,
    "reboot": _step_reboot,
}


# --- The run -----------------------------------------------------------------


async def _take(run_id: uuid.UUID, resume_from: str | None) -> TuneUpRun | None:
    """Claim the run: a pending one by moving it to running, a running one
    (`resume_from` = the heartbeat reconcile saw) only if nobody wrote since."""
    async with db_session.AsyncSessionLocal() as db:
        run = await db.get(TuneUpRun, run_id)
        if run is None:
            return None
        if run.status == model.PENDING and resume_from is None:
            if not await tune_up.claim(db, run_id):
                return None
        elif run.status == model.RUNNING and resume_from is not None:
            taken = await db.execute(
                update(TuneUpRun)
                .where(
                    TuneUpRun.id == run_id,
                    TuneUpRun.status == model.RUNNING,
                    TuneUpRun.heartbeat_at == datetime.fromisoformat(resume_from),
                )
                .values(heartbeat_at=datetime.now(UTC))
                .execution_options(synchronize_session=False)
            )
            await db.commit()
            if getattr(taken, "rowcount", 0) != 1:
                return None
        else:
            return None
        await db.refresh(run)
        db.expunge(run)
        return run


async def _cancel_requested(run_id: uuid.UUID) -> bool:
    async with db_session.AsyncSessionLocal() as db:
        return bool(
            await db.scalar(select(TuneUpRun.cancel_requested_by).where(TuneUpRun.id == run_id))
        )


async def _finish(run_id: uuid.UUID, status: str | None, error: str | None = None) -> None:
    """Close the run (skipping what it never got to) and let the next start."""
    async with db_session.AsyncSessionLocal() as db:
        run = await db.get(TuneUpRun, run_id)
        if run is None:
            return
        reason = {"code": "cancelled"} if status == model.CANCELLED else {"code": "unreachable"}
        run.steps = [
            {**step, "status": tune_up.STEP_SKIPPED, "detail": reason}
            if step.get("status") == tune_up.STEP_PENDING
            else dict(step)
            for step in run.steps or []
        ]
        run.status = status or tune_up.overall(run.steps)
        run.error = error
        run.finished_at = datetime.now(UTC)
        await db.commit()
        await tune_up.kick(db)


async def _run_tune_up(run_id: str, resume_from: str | None = None) -> None:
    run = await _take(uuid.UUID(run_id), resume_from)
    if run is None:
        return
    ctx = _Ctx(
        run_id=run.id,
        machine_id=run.machine_id,
        options=tune_up.Options.from_dict(run.options),
        started_by=(run.started_by or "tune-up")[:255],
        held=run.hold_order is not None,
    )
    beat = asyncio.create_task(_beat_forever(run.id))
    try:
        await _steps(run, ctx)
    finally:
        beat.cancel()


async def _steps(run: TuneUpRun, ctx: _Ctx) -> None:
    for index, step in enumerate(run.steps or []):
        if step.get("status") in tune_up.STEP_FINAL:
            continue
        if await _cancel_requested(run.id):
            await _finish(run.id, model.CANCELLED)
            return
        key = str(step.get("key"))
        runner = STEP_RUNNERS.get(key)
        if runner is None:
            await _save_step(run.id, index, status=tune_up.STEP_SKIPPED)
            continue
        if step.get("status") != tune_up.STEP_RUNNING:
            await _save_step(
                run.id, index, status=tune_up.STEP_RUNNING, started_at=_now_iso()
            )
        try:
            status, detail = await runner(ctx, dict(step.get("ref") or {}), index)
        except Exception as exc:  # a step's own bug must not leave the run open
            logger.exception("Tune-up step %s failed on %s", key, ctx.machine_id)
            status, detail = tune_up.STEP_FAILED, {"error": str(exc)[:500] or type(exc).__name__}
        await _save_step(run.id, index, status=status, detail=detail, finished_at=_now_iso())
        if key == "refresh" and status == tune_up.STEP_FAILED:
            await _finish(run.id, model.FAILED, (detail or {}).get("error"))
            return
    await _finish(run.id, None)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


async def _reconcile_tune_up_runs() -> int:
    """Give runs whose task stopped to a new one, re-send runs whose queue
    message was lost, and start waiting ones. Returns runs handed over."""
    now = datetime.now(UTC)
    handed = 0
    async with db_session.AsyncSessionLocal() as db:
        stale = (
            await db.execute(
                select(TuneUpRun.id, TuneUpRun.heartbeat_at).where(
                    TuneUpRun.status == model.RUNNING,
                    TuneUpRun.heartbeat_at < now - tune_up.STALE_AFTER,
                )
            )
        ).all()
        for run_id, beat in stale:
            run_tune_up.delay(str(run_id), resume_from=beat.isoformat() if beat else None)
            handed += 1
        lost = (
            await db.execute(
                select(TuneUpRun).where(
                    TuneUpRun.status == model.PENDING,
                    TuneUpRun.queued_at < now - tune_up.REQUEUE_AFTER,
                )
            )
        ).scalars().all()
        for run in lost:
            run.queued_at = None
        await db.commit()
        await tune_up.kick(db)
    return handed


@celery_app.task(name="app.tasks.tune_up.run_tune_up", time_limit=TASK_TIME_LIMIT_SECONDS)
def run_tune_up(run_id: str, resume_from: str | None = None) -> None:
    asyncio.run(_run_tune_up(run_id, resume_from))


@celery_app.task(name="app.tasks.tune_up.reconcile_tune_up_runs", time_limit=120)
def reconcile_tune_up_runs() -> int:
    return asyncio.run(_reconcile_tune_up_runs())
