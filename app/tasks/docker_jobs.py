"""Background work of the Docker tab: running `DockerJob`s, reading a
machine's Docker for the pages, the file browser's reads and writes, and
the Git stacks' auto-sync.

**Jobs run detached on the machine** (`app.ssh.detached_jobs`): a task
starts the job's script and reads its log until it ends. When the task
stops first — the worker restarts, or the container being updated is one
debcontrol itself needs — the job carries on, and `reconcile_docker_jobs`
(every minute, and right after a worker starts) resumes reading it.

**One job at a time per machine.** A job only starts when no other job
runs on the same machine; the rest wait as "pending" and the next one
starts when the running one ends (`_start_next`). Two updates never
replace containers at the same time, a backup never runs while a stack
is being redeployed, and an "Update all" goes container by container.

**A job is claimed once.** Starting moves it from pending to running in
one statement under a lock on its machine's row; resuming takes it only
if its heartbeat is the one the sweep saw. The same job queued twice
runs once.

The same two-part shape as `app.tasks.jobs`: `async def _x()` does the
work and `@celery_app.task def x()` only `asyncio.run`s it. Sessions are
opened through `db_session.AsyncSessionLocal()` (fork safety).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.app_settings import get_or_create_app_settings
from app.db import session as db_session
from app.db.models.docker import (
    DockerBackup,
    DockerJob,
    DockerJobKind,
    DockerJobStatus,
    DockerStack,
    StackSource,
)
from app.db.models.machine import Machine
from app.db.models.notification_rule import NotificationEventType
from app.services import docker_backups, docker_jobs, docker_scans, docker_stacks
from app.services.docker_gate import evaluate as evaluate_gate
from app.services.docker_gate import normalize_gate
from app.services.live_updates import KIND_DOCKER, publish_machine_event
from app.services.notifications import notify
from app.ssh import detached_jobs, docker_files
from app.ssh.credentials import resolve_machine_credential
from app.ssh.docker_cli import (
    DOCKER_ACCESS_PROBE,
    DOCKER_NO_ACCESS_MARKER,
    NO_ACCESS_MESSAGE,
    DockerAccessError,
    DockerCommandError,
    is_image_id_valid,
    q,
    run_binary,
    run_script,
)
from app.ssh.docker_compose import (
    STACKS_DIR,
    build_read_file_command,
    build_remote_head_command,
    build_remove_script,
    build_stack_action_script,
    parse_commit,
)
from app.ssh.docker_compose import failed_step as compose_failed_step
from app.ssh.docker_inventory import read_inventory
from app.ssh.docker_prune import (
    PruneOptions,
    build_prune_script,
    parse_reclaimed_bytes,
    parse_removed_counts,
)
from app.ssh.docker_scan import MAX_IMAGES as MAX_SCAN_IMAGES
from app.ssh.docker_scan import build_scan_script, parse_scan_output
from app.ssh.docker_update import (
    ContainerPlan,
    build_create_payload,
    build_plan_command,
    build_pull_script,
    build_recreate_script,
    build_retag_command,
    parse_plan_output,
    parse_pull_output,
    parse_recreate_output,
    plan_from_inspect,
)
from app.ssh.exceptions import HostKeyError, SSHConnectionError
from app.ssh.restic import (
    build_backup_script,
    build_check_script,
    build_forget_script,
    build_restore_script,
    build_snapshots_script,
    parse_backup_summary,
    parse_snapshots,
)
from app.ssh.restic import failed_step as restic_failed_step
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

AREA = "docker"

# The probe in front of every job script: in a job, no access is an error
# (exit 3), not the read-only "nothing to show" of `DOCKER_ACCESS_PROBE`.
_JOB_PROBE = DOCKER_ACCESS_PROBE.replace("exit 0", "exit 3")

# How long each kind of job may run on the machine.
_TIMEOUTS: dict[str, int] = {
    DockerJobKind.CONTAINER_UPDATE: 45 * 60,
    DockerJobKind.CONTAINER_ROLLBACK: 20 * 60,
    DockerJobKind.STACK_ACTION: 30 * 60,
    DockerJobKind.STACK_DEPLOY: 45 * 60,
    DockerJobKind.IMAGE_SCAN: 2 * 60 * 60,
    DockerJobKind.PRUNE: 60 * 60,
    DockerJobKind.BACKUP_RUN: 12 * 60 * 60,
    DockerJobKind.BACKUP_CHECK: 6 * 60 * 60,
    DockerJobKind.BACKUP_FORGET: 3 * 60 * 60,
    DockerJobKind.BACKUP_RESTORE: 12 * 60 * 60,
}
# Celery's kill switch, above the longest job.
_JOB_TASK_TIME_LIMIT = 12 * 60 * 60 + 30 * 60
_SHORT_TASK_TIME_LIMIT = 600

_HEARTBEAT_SECONDS = 20
_HEARTBEAT_STALE_SECONDS = 120
_PROGRESS_COMMIT_SECONDS = 2.0
# A pending job is nudged again at most this often, and given up after.
_KICK_AGAIN_SECONDS = 10 * 60
_PENDING_GIVE_UP = timedelta(hours=24)

RESUMED_NOTE = "[debcontrol] Reconnected after debcontrol restarted."


class _TryLaterError(Exception):
    """The job stays running; the next sweep comes back to it."""


class _JobFailedError(Exception):
    """The job ends as failed, with this message."""


class _NothingToDoError(Exception):
    """The job ends as skipped: there was nothing for it to do."""


@dataclass
class _Context:
    session: AsyncSession
    job: DockerJob
    machine: Machine
    secret: str | None
    connect_timeout: int
    result: dict[str, Any] = field(default_factory=dict)

    @property
    def params(self) -> dict[str, Any]:
        return dict(self.job.params or {})

    async def save(self) -> None:
        self.job.result = dict(self.result)
        await self.session.commit()

    async def short(self, script: str, *, run_seconds: int = 120) -> str:
        """Run a short Docker script; raises on no access or a failure."""
        output = await run_script(
            self.machine,
            self.secret,
            self.connect_timeout,
            script,
            run_timeout_seconds=run_seconds,
        )
        if output.exit_status != 0:
            raise DockerCommandError(output.output.strip()[-500:] or "The command failed.")
        return output.output


_GATE_MESSAGES = {
    "not_scanned": "the new image could not be scanned",
    "old_not_scanned": "the running image has no scan to compare with",
    "critical": "the new image has critical vulnerabilities",
    "high": "the new image has critical or high vulnerabilities",
    "worse": "the new image has more critical and high vulnerabilities than the running one",
}


def gate_message(gate: str, reason: str) -> str:
    return f"Stopped by the vulnerability gate ({gate}): {_GATE_MESSAGES.get(reason, reason)}."


def remote_id(job_id: uuid.UUID, phase: str) -> str:
    return str(uuid.uuid5(job_id, phase))


def _visible_output(text: str) -> str:
    """The job's output as stored and shown: the scanners' finding lines
    (thousands of them) are kept with the scan, not in the log."""
    return "\n".join(line for line in text.splitlines() if not line.startswith("V\t"))


# --- Claiming, heartbeat, closing -------------------------------------------


async def _claim(session: AsyncSession, job: DockerJob) -> bool:
    """pending -> running, only when nothing else runs on the machine."""
    # Serializes claims for one machine (a no-op on SQLite in tests).
    await session.execute(
        select(Machine.id).where(Machine.id == job.machine_id).with_for_update()
    )
    busy = await session.execute(
        select(DockerJob.id)
        .where(
            DockerJob.machine_id == job.machine_id,
            DockerJob.status == DockerJobStatus.RUNNING,
            DockerJob.id != job.id,
        )
        .limit(1)
    )
    if busy.first() is not None:
        await session.rollback()
        return False
    now = datetime.now(UTC)
    claimed = await session.execute(
        update(DockerJob)
        .where(DockerJob.id == job.id, DockerJob.status == DockerJobStatus.PENDING)
        .values(status=DockerJobStatus.RUNNING, started_at=now, heartbeat_at=now)
        .execution_options(synchronize_session=False)
    )
    await session.commit()
    return getattr(claimed, "rowcount", 0) == 1


@contextlib.asynccontextmanager
async def _heartbeat(job_id: uuid.UUID) -> AsyncIterator[None]:
    async def beat() -> None:
        while True:
            await asyncio.sleep(_HEARTBEAT_SECONDS)
            try:
                async with db_session.AsyncSessionLocal() as beat_session:
                    await beat_session.execute(
                        update(DockerJob)
                        .where(DockerJob.id == job_id, DockerJob.status == DockerJobStatus.RUNNING)
                        .values(heartbeat_at=datetime.now(UTC))
                        .execution_options(synchronize_session=False)
                    )
                    await beat_session.commit()
            except Exception as exc:  # a missed beat must not stop the job
                logger.warning("Docker job %s heartbeat failed: %s", job_id, exc)

    task = asyncio.create_task(beat())
    try:
        yield
    finally:
        task.cancel()
        await asyncio.wait({task})


async def _close(
    ctx: _Context, status: DockerJobStatus, error: str | None = None
) -> bool:
    """Record how the job ended — once. Returns False when someone else
    closed it first."""
    job = ctx.job
    closed = await ctx.session.execute(
        update(DockerJob)
        .where(DockerJob.id == job.id, DockerJob.status == DockerJobStatus.RUNNING)
        .values(
            status=status,
            error=error[:1024] if error else None,
            output=job.output,
            result=dict(ctx.result) or None,
            finished_at=datetime.now(UTC),
        )
        .execution_options(synchronize_session=False)
    )
    await ctx.session.commit()
    if getattr(closed, "rowcount", 0) != 1:
        return False
    await ctx.session.refresh(job)
    await _after_close(ctx, status)
    return True


async def _after_close(ctx: _Context, status: DockerJobStatus) -> None:
    job, machine, session = ctx.job, ctx.machine, ctx.session
    details = job.error or ""
    if job.kind == DockerJobKind.CONTAINER_UPDATE:
        event = {
            DockerJobStatus.SUCCEEDED: NotificationEventType.DOCKER_UPDATE_SUCCEEDED,
            DockerJobStatus.FAILED: NotificationEventType.DOCKER_UPDATE_FAILED,
            DockerJobStatus.BLOCKED: NotificationEventType.DOCKER_UPDATE_BLOCKED,
        }.get(status)
        if event is not None:
            await notify(
                session,
                event,
                machine=machine,
                context={"container": job.target, "details": details},
            )
    elif job.kind in (DockerJobKind.STACK_DEPLOY, DockerJobKind.STACK_ACTION):
        if status == DockerJobStatus.FAILED:
            await notify(
                session,
                NotificationEventType.DOCKER_STACK_FAILED,
                machine=machine,
                context={"stack": job.target, "details": details},
            )
    elif job.kind == DockerJobKind.BACKUP_RUN and status == DockerJobStatus.FAILED:
        await notify(
            session,
            NotificationEventType.DOCKER_BACKUP_FAILED,
            machine=machine,
            context={"backup": job.target, "details": details},
        )
    if job.kind in (
        DockerJobKind.CONTAINER_UPDATE,
        DockerJobKind.CONTAINER_ROLLBACK,
        DockerJobKind.STACK_ACTION,
        DockerJobKind.STACK_DEPLOY,
        DockerJobKind.PRUNE,
        DockerJobKind.BACKUP_RESTORE,
    ):
        # What runs changed: refresh the container list and image checks.
        from app.tasks import jobs as machine_jobs

        machine_jobs.sample_machine_monitoring.delay(str(machine.id))
        if status == DockerJobStatus.SUCCEEDED:
            machine_jobs.check_machine_image_updates.delay(str(machine.id))
    await publish_machine_event(str(machine.id), KIND_DOCKER)
    await _start_next(session, machine.id)


async def _start_next(session: AsyncSession, machine_id: uuid.UUID) -> None:
    """Queue the machine's oldest pending job, if any."""
    result = await session.execute(
        select(DockerJob.id)
        .where(DockerJob.machine_id == machine_id, DockerJob.status == DockerJobStatus.PENDING)
        .order_by(DockerJob.created_at, DockerJob.id)
        .limit(1)
    )
    row = result.first()
    if row is not None:
        run_docker_job.delay(str(row[0]))


# --- Following one detached phase --------------------------------------------


async def _run_phase(
    ctx: _Context,
    phase: str,
    build: Callable[[], Awaitable[str]],
) -> tuple[int | None, str]:
    """Start the phase's script (unless this phase was started before —
    a resumed job) and read it to the end. Returns (exit status, output)."""
    job = ctx.job
    remote = remote_id(job.id, phase)
    timeout = _TIMEOUTS.get(job.kind, 30 * 60)
    if ctx.result.get("phase") != phase:
        script = await build()
        await detached_jobs.start(
            ctx.machine, ctx.secret, AREA, remote, _JOB_PROBE + script, ctx.connect_timeout
        )
        # Recorded after starting: a resumed job that finds this phase
        # follows it rather than starting it again.
        ctx.result["phase"] = phase
        ctx.result.setdefault("phases", []).append(phase)
        await ctx.save()
    earlier = job.output or ""
    last_commit = 0.0

    async def persist(text: str) -> None:
        nonlocal last_commit
        now = time.monotonic()
        if now - last_commit < _PROGRESS_COMMIT_SECONDS:
            return
        last_commit = now
        job.output = docker_jobs.truncate_output(earlier + _visible_output(text))
        await ctx.session.commit()

    started = job.started_at or datetime.now(UTC)
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    remaining = timeout - (datetime.now(UTC) - started).total_seconds()
    followed = await detached_jobs.follow(
        ctx.machine,
        ctx.secret,
        AREA,
        remote,
        ctx.connect_timeout,
        max(remaining, 60),
        on_output=persist,
    )
    job.output = docker_jobs.truncate_output(earlier + _visible_output(followed.output))
    await ctx.session.commit()
    if DOCKER_NO_ACCESS_MARKER in followed.output.splitlines()[:3]:
        raise DockerAccessError(NO_ACCESS_MESSAGE)
    if followed.state == "finished":
        if followed.exit_status == 3 and DOCKER_NO_ACCESS_MARKER in followed.output:
            raise DockerAccessError(NO_ACCESS_MESSAGE)
        return followed.exit_status, followed.output
    if followed.state == "timeout":
        raise _JobFailedError(
            f"The job did not finish within {timeout // 60} minutes. It may still be "
            "running on the machine."
        )
    if followed.state == "unreachable":
        if remaining > 0:
            raise _TryLaterError(followed.error or "unreachable")
        raise _JobFailedError(
            "The machine could not be reached to see how the job ended"
            + (f" ({followed.error})." if followed.error else ".")
        )
    if followed.state == "lost":
        raise _JobFailedError(
            "The job stopped on the machine before it finished (was the machine restarted?)."
        )
    raise _JobFailedError("The job's log on the machine is gone; how it ended is unknown.")


# --- Containers --------------------------------------------------------------


async def _inspect(
    ctx: _Context, name: str
) -> tuple[ContainerPlan, dict[str, Any], dict[str, Any]]:
    output = await ctx.short(build_plan_command(name))
    container, image = parse_plan_output(output)
    return plan_from_inspect(container, image), container, image


def _check_updatable(plan: ContainerPlan) -> None:
    if not plan.ref or "@" in plan.ref or plan.ref.startswith("sha256:"):
        raise _JobFailedError(
            "This container was created from a fixed image (an id or a digest), "
            "so there is no newer image of its tag to update to."
        )
    if not plan.repo_digests:
        raise _JobFailedError(
            "This container's image was built on the machine, not pulled from a "
            "registry, so it can't be updated by pulling."
        )


async def _job_container_update(ctx: _Context) -> None:
    name = ctx.job.target
    # Checked again when the job runs: the machine may have been recognised
    # as debcontrol's own host since the job was queued.
    await docker_jobs.check_container(ctx.session, ctx.machine, name)
    gate = normalize_gate(str(ctx.params.get("gate") or ""))
    if ctx.result.get("phase") in (None, "pull"):
        state: dict[str, Any] = {}

        async def build_pull() -> str:
            plan, _container, _image = await _inspect(ctx, name)
            _check_updatable(plan)
            state["plan"] = plan
            scan_old = None
            if gate == "worse" and docker_scans.counts_of(
                await docker_scans.get_scan(ctx.session, ctx.machine.id, plan.image_id)
            ) is None:
                scan_old = plan.image_id
            ctx.result.update(
                {"ref": plan.ref, "previous_image_id": plan.image_id, "gate_policy": gate}
            )
            return build_pull_script(
                plan.ref, current=plan.image_id, scan=gate != "off", scan_old=scan_old
            )

        status, output = await _run_phase(ctx, "pull", build_pull)
        pull = parse_pull_output(output)
        if pull.failed or status != 0:
            raise _JobFailedError("Pulling the image failed — see the output.")
        previous = str(ctx.result.get("previous_image_id") or "")
        ref = str(ctx.result.get("ref") or "")
        ctx.result["new_image_id"] = pull.new_id
        if not pull.new_id or not previous or pull.new_id == previous:
            ctx.result["note"] = "up_to_date"
            await _close(ctx, DockerJobStatus.SKIPPED)
            return
        if gate != "off":
            found = parse_scan_output(output)
            counts = await docker_scans.store(
                ctx.session, ctx.machine.id, found, {ref: pull.new_id, previous: previous}
            )
            old_counts = counts.get(previous) or docker_scans.counts_of(
                await docker_scans.get_scan(ctx.session, ctx.machine.id, previous)
            )
            verdict = evaluate_gate(gate, counts.get(pull.new_id), old_counts)
            ctx.result["gate"] = verdict.as_dict()
            await ctx.save()
            if not verdict.allowed:
                # The tag points at what runs again: nothing deploys the
                # stopped image by accident.
                with contextlib.suppress(DockerCommandError, SSHConnectionError):
                    await ctx.short(build_retag_command(previous, ref))
                await _close(ctx, DockerJobStatus.BLOCKED, gate_message(gate, verdict.reason))
                return

    async def build_recreate() -> str:
        plan, container, image = await _inspect(ctx, name)
        previous = str(ctx.result.get("previous_image_id") or plan.image_id)
        if plan.is_compose:
            return build_recreate_script(plan, previous_image_id=previous)
        payload, extra = build_create_payload(container, image)
        return build_recreate_script(
            plan, payload=payload, extra_networks=extra, previous_image_id=previous
        )

    status, output = await _run_phase(ctx, "recreate", build_recreate)
    await _finish_recreate(ctx, status, output)


async def _finish_recreate(ctx: _Context, status: int | None, output: str) -> None:
    outcome = parse_recreate_output(output)
    ctx.result["restored"] = outcome.restored
    if status == 0 and outcome.done:
        await _close(ctx, DockerJobStatus.SUCCEEDED)
        return
    if outcome.restored:
        message = "The new container did not start or stay up; the previous one was put back."
    elif outcome.failed_step:
        message = f"The update failed at step \"{outcome.failed_step}\" — see the output."
    else:
        message = "The update failed — see the output."
    await _close(ctx, DockerJobStatus.FAILED, message)


async def _job_container_rollback(ctx: _Context) -> None:
    name = ctx.job.target
    target = str(ctx.params.get("image_id") or "")
    await docker_jobs.check_container(ctx.session, ctx.machine, name)
    if not is_image_id_valid(target):
        raise _JobFailedError("There is no previous image to roll back to.")

    async def build() -> str:
        plan, container, image = await _inspect(ctx, name)
        try:
            await ctx.short(f"$D image inspect --format '{{{{.Id}}}}' {q(target)}")
        except DockerCommandError as exc:
            raise _JobFailedError(
                "The previous image is no longer on the machine (was it cleaned up?)."
            ) from exc
        ctx.result.update(
            {"ref": plan.ref, "previous_image_id": plan.image_id, "new_image_id": target}
        )
        if plan.is_compose:
            return build_recreate_script(plan, retag_to=target, previous_image_id=plan.image_id)
        payload, extra = build_create_payload(container, image)
        return build_recreate_script(
            plan,
            payload=payload,
            extra_networks=extra,
            retag_to=target,
            previous_image_id=plan.image_id,
        )

    status, output = await _run_phase(ctx, "recreate", build)
    await _finish_recreate(ctx, status, output)


# --- Stacks -----------------------------------------------------------------


async def _stack(ctx: _Context) -> DockerStack:
    if ctx.job.ref_id is None:
        raise _JobFailedError("Stack not found.")
    stack = await ctx.session.get(DockerStack, ctx.job.ref_id)
    if stack is None or stack.machine_id != ctx.machine.id:
        raise _JobFailedError("The stack was deleted.")
    return stack


async def _job_stack_deploy(ctx: _Context) -> None:
    stack = await _stack(ctx)
    await docker_jobs.check_project(ctx.session, ctx.machine, stack.name)
    pull = bool(ctx.params.get("pull", True))

    async def build() -> str:
        return docker_stacks.deploy_script(stack, pull=pull)

    status, output = await _run_phase(ctx, "run", build)
    commit = parse_commit(output)
    stack.last_checked_at = datetime.now(UTC)
    if status == 0 and "@@DC_DONE" in output:
        stack.deployed_commit = commit or (
            stack.deployed_commit if stack.source == StackSource.GIT else None
        )
        stack.deployed_hash = docker_stacks.content_hash(stack)
        stack.deployed_at = datetime.now(UTC)
        stack.last_status = "ok"
        stack.last_error = None
        ctx.result["commit"] = commit
        await ctx.session.commit()
        await _close(ctx, DockerJobStatus.SUCCEEDED)
        return
    step = compose_failed_step(output) or "deploy"
    message = f"The deployment failed at step \"{step}\" — see the output."
    stack.last_status = "failed"
    stack.last_error = message
    await ctx.session.commit()
    await _close(ctx, DockerJobStatus.FAILED, message)


async def _job_stack_action(ctx: _Context) -> None:
    params = ctx.params
    action = str(params.get("action") or "")
    if action != "start":
        await docker_jobs.check_project(ctx.session, ctx.machine, ctx.job.target)

    async def build() -> str:
        if action == "remove":
            stack = (
                await ctx.session.get(DockerStack, ctx.job.ref_id)
                if ctx.job.ref_id is not None
                else None
            )
            return build_remove_script(
                ctx.job.target,
                volumes=bool(params.get("volumes")),
                directory=(stack.directory or "") if stack is not None else "",
            )
        return build_stack_action_script(
            ctx.job.target,
            action,
            working_dir=str(params.get("working_dir") or ""),
            files=[str(f) for f in params.get("files") or []],
        )

    status, _output = await _run_phase(ctx, "run", build)
    if status == 0:
        if action == "remove" and ctx.job.ref_id is not None:
            stack = await ctx.session.get(DockerStack, ctx.job.ref_id)
            if stack is not None:
                await ctx.session.delete(stack)
                await ctx.session.commit()
        await _close(ctx, DockerJobStatus.SUCCEEDED)
        return
    await _close(ctx, DockerJobStatus.FAILED, f"docker compose exited with status {status}.")


# --- Images: scans and cleanup ----------------------------------------------


async def _refresh_scan_summary(ctx: _Context) -> None:
    """Which images the machine has and its containers use, to drop scans
    of images that are gone and summarize the rest. Best effort."""
    try:
        inventory = await read_inventory(
            ctx.machine, ctx.secret, ctx.connect_timeout, sections=("images", "inspect")
        )
    except (DockerCommandError, DockerAccessError, SSHConnectionError) as exc:
        logger.warning("Docker inventory after a scan failed for %s: %s", ctx.machine.name, exc)
        await docker_scans.summarize(ctx.session, ctx.machine, None)
        return
    present = {str(i.get("id")) for i in inventory.images if i.get("id")}
    in_use = {str(c.get("image_id")) for c in inventory.containers if c.get("image_id")}
    await docker_scans.forget_missing(ctx.session, ctx.machine.id, present)
    await docker_scans.summarize(ctx.session, ctx.machine, in_use)


async def _images_to_scan(ctx: _Context, scope: str) -> dict[str, str]:
    """{name to scan as: image id} for a scan by scope: the images the
    containers use ("in_use"), only those without a scan yet
    ("unscanned"), or every image on the machine ("all")."""
    inventory = await read_inventory(
        ctx.machine, ctx.secret, ctx.connect_timeout, sections=("images", "inspect")
    )
    existing = await docker_scans.scans_by_image(ctx.session, ctx.machine.id)
    chosen: dict[str, str] = {}
    for image in inventory.images:
        image_id = str(image.get("id") or "")
        if not image_id or image_id in chosen.values():
            continue
        if scope != "all" and not image.get("in_use"):
            continue
        if scope == "unscanned" and image_id in existing:
            continue
        chosen[str(image.get("ref") or image_id)] = image_id
    return dict(list(chosen.items())[:MAX_SCAN_IMAGES])


async def _job_image_scan(ctx: _Context) -> None:
    images: dict[str, str] = {
        str(k): str(v) for k, v in dict(ctx.params.get("images") or {}).items()
    }
    scope = str(ctx.params.get("scope") or "")

    async def build() -> str:
        if scope:
            images.update(await _images_to_scan(ctx, scope))
            if not images:
                raise _NothingToDoError
        ctx.result["images"] = dict(images)
        return build_scan_script(list(images))

    try:
        _status, output = await _run_phase(ctx, "run", build)
    except _NothingToDoError:
        ctx.result["note"] = "nothing_to_scan"
        await _close(ctx, DockerJobStatus.SKIPPED)
        return
    images = {str(k): str(v) for k, v in dict(ctx.result.get("images") or images).items()}
    found = parse_scan_output(output)
    counts = await docker_scans.store(ctx.session, ctx.machine.id, found, images)
    await _refresh_scan_summary(ctx)
    scanned = sum(1 for c in counts.values() if c is not None)
    ctx.result.update({"scanned": scanned, "failed": len(counts) - scanned})
    await ctx.session.commit()
    if scanned == 0:
        errors = "; ".join(
            f"{name}: {message}" for r in found for name, message in r.errors.items()
        )
        await _close(ctx, DockerJobStatus.FAILED, errors[:1000] or "No image could be scanned.")
        return
    await _close(ctx, DockerJobStatus.SUCCEEDED)


async def _job_prune(ctx: _Context) -> None:
    options = PruneOptions.from_dict(ctx.params)

    async def build() -> str:
        return build_prune_script(options)

    status, output = await _run_phase(ctx, "run", build)
    ctx.result.update(
        {"reclaimed_bytes": parse_reclaimed_bytes(output), "removed": parse_removed_counts(output)}
    )
    if status == 0:
        await _close(ctx, DockerJobStatus.SUCCEEDED)
    else:
        await _close(ctx, DockerJobStatus.FAILED, "Part of the cleanup failed — see the output.")


# --- Backups ----------------------------------------------------------------


async def _backup(ctx: _Context) -> DockerBackup:
    if ctx.job.ref_id is None:
        raise _JobFailedError("Backup not found.")
    backup = await ctx.session.get(DockerBackup, ctx.job.ref_id)
    if backup is None or backup.machine_id != ctx.machine.id:
        raise _JobFailedError("The backup was deleted.")
    return backup


def _restic_error(output: str, default: str) -> str:
    step = restic_failed_step(output)
    tail = " ".join(output.strip().splitlines()[-3:])[-300:]
    return f"restic failed at step \"{step}\": {tail}" if step else default


async def _job_backup_run(ctx: _Context) -> None:
    backup = await _backup(ctx)

    async def build() -> str:
        if backup.stop_containers:
            await docker_jobs.check_volumes(ctx.session, ctx.machine, list(backup.volumes or []))
        config = docker_backups.config_for(backup, ctx.machine)
        return build_backup_script(
            config,
            stop_containers=backup.stop_containers,
            keep=docker_backups.keep_of(backup),
        )

    status, output = await _run_phase(ctx, "run", build)
    now = datetime.now(UTC)
    summary = parse_backup_summary(output)
    backup.last_backup_at = now
    if status == 0 and summary.snapshot_id:
        backup.last_backup_status = "ok"
        backup.last_success_at = now
        backup.last_snapshot_id = summary.snapshot_id
        backup.last_backup_bytes = summary.bytes_added
        backup.last_error = None
        ctx.machine.docker_backup_ok_at = now
        ctx.result.update(
            {
                "snapshot_id": summary.snapshot_id,
                "bytes_added": summary.bytes_added,
                "bytes_processed": summary.bytes_processed,
                "files": summary.files,
            }
        )
        await ctx.session.commit()
        await _close(ctx, DockerJobStatus.SUCCEEDED)
        return
    message = _restic_error(output, "The backup failed — see the output.")
    backup.last_backup_status = "failed"
    backup.last_error = message[:1024]
    await ctx.session.commit()
    await _close(ctx, DockerJobStatus.FAILED, message)


async def _job_backup_check(ctx: _Context) -> None:
    backup = await _backup(ctx)
    percent = int(ctx.params.get("read_data_percent") or 0)

    async def build() -> str:
        return build_check_script(
            docker_backups.config_for(backup, ctx.machine), read_data_percent=percent
        )

    status, output = await _run_phase(ctx, "run", build)
    backup.last_check_at = datetime.now(UTC)
    backup.last_check_status = "ok" if status == 0 else "failed"
    await ctx.session.commit()
    if status == 0:
        await _close(ctx, DockerJobStatus.SUCCEEDED)
    else:
        await _close(
            ctx, DockerJobStatus.FAILED, _restic_error(output, "The repository check failed.")
        )


async def _job_backup_forget(ctx: _Context) -> None:
    backup = await _backup(ctx)

    async def build() -> str:
        return build_forget_script(
            docker_backups.config_for(backup, ctx.machine), keep=docker_backups.keep_of(backup)
        )

    status, output = await _run_phase(ctx, "run", build)
    if status == 0:
        await _close(ctx, DockerJobStatus.SUCCEEDED)
    else:
        await _close(ctx, DockerJobStatus.FAILED, _restic_error(output, "Pruning failed."))


async def _job_backup_restore(ctx: _Context) -> None:
    backup = await _backup(ctx)
    params = ctx.params
    volumes = [str(v) for v in params.get("volumes") or []]
    paths = [str(p) for p in params.get("paths") or []]

    async def build() -> str:
        await docker_jobs.check_volumes(ctx.session, ctx.machine, volumes)
        config = docker_backups.config_for(backup, ctx.machine, volumes=volumes, paths=paths)
        return build_restore_script(
            config, str(params.get("snapshot") or ""), delete=bool(params.get("delete"))
        )

    status, output = await _run_phase(ctx, "run", build)
    if status == 0 and "@@DC_DONE" in output:
        await _close(ctx, DockerJobStatus.SUCCEEDED)
    else:
        await _close(ctx, DockerJobStatus.FAILED, _restic_error(output, "The restore failed."))


_HANDLERS: dict[str, Callable[[_Context], Awaitable[None]]] = {
    DockerJobKind.CONTAINER_UPDATE: _job_container_update,
    DockerJobKind.CONTAINER_ROLLBACK: _job_container_rollback,
    DockerJobKind.STACK_DEPLOY: _job_stack_deploy,
    DockerJobKind.STACK_ACTION: _job_stack_action,
    DockerJobKind.IMAGE_SCAN: _job_image_scan,
    DockerJobKind.PRUNE: _job_prune,
    DockerJobKind.BACKUP_RUN: _job_backup_run,
    DockerJobKind.BACKUP_CHECK: _job_backup_check,
    DockerJobKind.BACKUP_FORGET: _job_backup_forget,
    DockerJobKind.BACKUP_RESTORE: _job_backup_restore,
}


async def _execute(session: AsyncSession, job: DockerJob) -> None:
    app_settings = await get_or_create_app_settings(session)
    machine = await session.get(Machine, job.machine_id)
    ctx = _Context(
        session=session,
        job=job,
        machine=machine,  # type: ignore[arg-type]  # checked just below
        secret=None,
        connect_timeout=app_settings.ssh_connect_timeout,
        result=dict(job.result or {}),
    )
    if machine is None:
        return
    handler = _HANDLERS.get(job.kind)
    if handler is None:
        await _close(ctx, DockerJobStatus.FAILED, f"Unknown job kind {job.kind!r}.")
        return
    if not machine.host_key_fingerprint:
        await _close(ctx, DockerJobStatus.FAILED, "No pinned host key fingerprint yet.")
        return
    ctx.secret = await resolve_machine_credential(machine, session)
    async with _heartbeat(job.id):
        try:
            await handler(ctx)
        except _TryLaterError:
            raise
        except docker_jobs.ProtectedError:
            await _close(ctx, DockerJobStatus.FAILED, docker_jobs.PROTECTED_MESSAGE)
        except (_JobFailedError, DockerCommandError, DockerAccessError, ValueError) as exc:
            await _close(ctx, DockerJobStatus.FAILED, str(exc) or type(exc).__name__)
        except HostKeyError as exc:
            await _close(ctx, DockerJobStatus.FAILED, str(exc))
        except (SSHConnectionError, TimeoutError, OSError) as exc:
            await _close(ctx, DockerJobStatus.FAILED, str(exc) or type(exc).__name__)
        except Exception:
            logger.exception("Docker job %s (%s) failed unexpectedly", job.id, job.kind)
            await _close(ctx, DockerJobStatus.FAILED, "Unexpected error — see the worker log.")


async def _run_docker_job(job_id: str) -> None:
    async with db_session.AsyncSessionLocal() as session:
        job = await session.get(DockerJob, uuid.UUID(job_id))
        if job is None or job.status != DockerJobStatus.PENDING:
            return
        if not await _claim(session, job):
            return
        await session.refresh(job)
        machine = await session.get(Machine, job.machine_id)
        if machine is None:
            return
        await _execute(session, job)


async def _resume_docker_job(job_id: str, claimed_at: str | None = None) -> None:
    async with db_session.AsyncSessionLocal() as session:
        job = await session.get(DockerJob, uuid.UUID(job_id))
        if job is None or job.status != DockerJobStatus.RUNNING:
            return
        beat = job.heartbeat_at
        if beat is not None and beat.tzinfo is None:
            beat = beat.replace(tzinfo=UTC)
        if claimed_at is not None and (beat is None or beat != datetime.fromisoformat(claimed_at)):
            return
        taken = await session.execute(
            update(DockerJob)
            .where(
                DockerJob.id == job.id,
                DockerJob.status == DockerJobStatus.RUNNING,
                DockerJob.heartbeat_at == job.heartbeat_at,
            )
            .values(heartbeat_at=datetime.now(UTC))
            .execution_options(synchronize_session=False)
        )
        await session.commit()
        if getattr(taken, "rowcount", 0) != 1:
            return
        await session.refresh(job)
        if RESUMED_NOTE not in (job.output or "")[-500:]:
            job.output = docker_jobs.truncate_output(f"{job.output or ''}\n{RESUMED_NOTE}\n")
            await session.commit()
        await _execute(session, job)


@celery_app.task(name="app.tasks.docker_jobs.run_docker_job", time_limit=_JOB_TASK_TIME_LIMIT)
def run_docker_job(job_id: str) -> None:
    with contextlib.suppress(_TryLaterError):
        asyncio.run(_run_docker_job(job_id))


@celery_app.task(name="app.tasks.docker_jobs.resume_docker_job", time_limit=_JOB_TASK_TIME_LIMIT)
def resume_docker_job(job_id: str, claimed_at: str | None = None) -> None:
    with contextlib.suppress(_TryLaterError):
        asyncio.run(_resume_docker_job(job_id, claimed_at))


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def _reconcile_docker_jobs() -> dict[str, int]:
    """Every minute: resume running jobs nobody follows, start pending ones
    nobody started, give up on ones pending for a day."""
    now = datetime.now(UTC)
    counts = {"resumed": 0, "kicked": 0, "abandoned": 0}
    async with db_session.AsyncSessionLocal() as session:
        stale = now - timedelta(seconds=_HEARTBEAT_STALE_SECONDS)
        result = await session.execute(
            select(DockerJob).where(
                DockerJob.status == DockerJobStatus.RUNNING,
                (DockerJob.heartbeat_at.is_(None)) | (DockerJob.heartbeat_at < stale),
            )
        )
        for job in result.scalars().all():
            claimed = await session.execute(
                update(DockerJob)
                .where(
                    DockerJob.id == job.id,
                    DockerJob.status == DockerJobStatus.RUNNING,
                    DockerJob.heartbeat_at == job.heartbeat_at,
                )
                .values(heartbeat_at=now)
                .execution_options(synchronize_session=False)
            )
            await session.commit()
            if getattr(claimed, "rowcount", 0) == 1:
                resume_docker_job.delay(str(job.id), now.isoformat())
                counts["resumed"] += 1

        pending = await session.execute(
            select(DockerJob)
            .where(DockerJob.status == DockerJobStatus.PENDING)
            .order_by(DockerJob.created_at, DockerJob.id)
        )
        running = await session.execute(
            select(DockerJob.machine_id).where(DockerJob.status == DockerJobStatus.RUNNING)
        )
        busy = {row[0] for row in running.all()}
        seen: set[uuid.UUID] = set()
        for job in pending.scalars().all():
            created = _aware(job.created_at)
            if now - created > _PENDING_GIVE_UP:
                job.status = DockerJobStatus.FAILED
                job.error = "The job never started (the machine stayed busy or unreachable)."
                job.finished_at = now
                counts["abandoned"] += 1
                continue
            if job.machine_id in busy or job.machine_id in seen:
                continue
            seen.add(job.machine_id)
            kicked = str((job.result or {}).get("kicked_at") or "")
            if kicked and (now - _aware(datetime.fromisoformat(kicked))).total_seconds() < (
                _KICK_AGAIN_SECONDS
            ):
                continue
            if (now - created).total_seconds() < 60:
                continue
            job.result = {**(job.result or {}), "kicked_at": now.isoformat()}
            run_docker_job.delay(str(job.id))
            counts["kicked"] += 1
        await session.commit()
    return counts


@celery_app.task(name="app.tasks.docker_jobs.reconcile_docker_jobs")
def reconcile_docker_jobs() -> dict[str, int]:
    return asyncio.run(_reconcile_docker_jobs())


async def _purge_old_docker_jobs() -> int:
    async with db_session.AsyncSessionLocal() as session:
        return await docker_jobs.purge_old(session)


@celery_app.task(name="app.tasks.docker_jobs.purge_old_docker_jobs")
def purge_old_docker_jobs() -> int:
    return asyncio.run(_purge_old_docker_jobs())


# --- Reads for the pages -----------------------------------------------------


async def _machine_and_secret(
    session: AsyncSession, machine_id: str
) -> tuple[Machine, str | None, int]:
    app_settings = await get_or_create_app_settings(session)
    machine = await session.get(Machine, uuid.UUID(machine_id))
    if machine is None:
        raise DockerCommandError("Machine not found.")
    if not machine.host_key_fingerprint:
        raise DockerCommandError("No pinned host key fingerprint yet.")
    secret = await resolve_machine_credential(machine, session)
    return machine, secret, app_settings.ssh_connect_timeout


def _error(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, DockerAccessError):
        return {"ok": False, "error": NO_ACCESS_MESSAGE, "no_access": True}
    return {"ok": False, "error": str(exc) or type(exc).__name__}


_READ_ERRORS = (DockerCommandError, DockerAccessError, SSHConnectionError, TimeoutError, OSError)


async def _docker_inventory(machine_id: str, sections: list[str]) -> dict[str, Any]:
    """The machine's containers, images, volumes, networks and Compose
    projects, read live (`app.ssh.docker_inventory`)."""
    async with db_session.AsyncSessionLocal() as session:
        try:
            machine, secret, timeout = await _machine_and_secret(session, machine_id)
            inventory = await read_inventory(machine, secret, timeout, sections=tuple(sections))
        except _READ_ERRORS as exc:
            return _error(exc)
        if "images" in sections and "inspect" in sections:
            present = {str(i.get("id")) for i in inventory.images if i.get("id")}
            in_use = {str(c.get("image_id")) for c in inventory.containers if c.get("image_id")}
            await docker_scans.forget_missing(session, machine.id, present)
            await docker_scans.summarize(session, machine, in_use)
            await session.commit()
        return {"ok": True, "inventory": inventory.as_dict()}


@celery_app.task(name="app.tasks.docker_jobs.docker_inventory", time_limit=_SHORT_TASK_TIME_LIMIT)
def docker_inventory(machine_id: str, sections: list[str]) -> dict[str, Any]:
    return asyncio.run(_docker_inventory(machine_id, sections))


async def _docker_compose_file(machine_id: str, path: str) -> dict[str, Any]:
    async with db_session.AsyncSessionLocal() as session:
        try:
            machine, secret, timeout = await _machine_and_secret(session, machine_id)
            output = await run_script(machine, secret, timeout, build_read_file_command(path))
        except _READ_ERRORS as exc:
            return _error(exc)
    if output.exit_status != 0:
        return {"ok": False, "error": output.output.strip()[-300:] or "Could not read the file."}
    return {"ok": True, "content": output.output}


@celery_app.task(
    name="app.tasks.docker_jobs.docker_compose_file", time_limit=_SHORT_TASK_TIME_LIMIT
)
def docker_compose_file(machine_id: str, path: str) -> dict[str, Any]:
    return asyncio.run(_docker_compose_file(machine_id, path))


async def _docker_backup_snapshots(backup_id: str) -> dict[str, Any]:
    async with db_session.AsyncSessionLocal() as session:
        backup = await session.get(DockerBackup, uuid.UUID(backup_id))
        if backup is None:
            return {"ok": False, "error": "Backup not found."}
        try:
            machine, secret, timeout = await _machine_and_secret(session, str(backup.machine_id))
            script = build_snapshots_script(docker_backups.config_for(backup, machine))
            output = await run_script(machine, secret, timeout, script, run_timeout_seconds=300)
        except _READ_ERRORS as exc:
            return _error(exc)
    if output.exit_status != 0:
        tail = output.output.strip().splitlines()[-3:]
        return {"ok": False, "error": " ".join(tail)[-400:] or "restic failed."}
    return {"ok": True, "snapshots": parse_snapshots(output.output)}


@celery_app.task(
    name="app.tasks.docker_jobs.docker_backup_snapshots", time_limit=_SHORT_TASK_TIME_LIMIT
)
def docker_backup_snapshots(backup_id: str) -> dict[str, Any]:
    return asyncio.run(_docker_backup_snapshots(backup_id))


# --- File browser -------------------------------------------------------------


async def _docker_files(
    machine_id: str,
    op: str,
    kind: str,
    name: str,
    path: str,
    data_b64: str = "",
    filename: str = "",
) -> dict[str, Any]:
    """One file-browser operation on a container or a volume
    (`app.ssh.docker_files`): list, read (to edit), download, write,
    upload, mkdir, delete."""
    async with db_session.AsyncSessionLocal() as session:
        try:
            machine, secret, timeout = await _machine_and_secret(session, machine_id)
            target = docker_files.Target(kind, name)  # type: ignore[arg-type]
            return await _files_op(machine, secret, timeout, target, op, path, data_b64, filename)
        except _READ_ERRORS as exc:
            return _error(exc)


async def _files_op(
    machine: Machine,
    secret: str | None,
    timeout: int,  # noqa: ASYNC109 - the SSH connect timeout, not a deadline
    target: docker_files.Target,
    op: str,
    path: str,
    data_b64: str,
    filename: str,
) -> dict[str, Any]:
    if op == "list":
        output = await run_script(
            machine, secret, timeout, docker_files.build_list_command(target, path)
        )
        entries = docker_files.parse_listing(output.output)
        if entries is None:
            return {"ok": False, "error": "No such directory.", "missing": True}
        if output.exit_status not in (0, None) and not entries:
            return {"ok": False, "error": output.output.strip()[-300:] or "Could not list."}
        return {"ok": True, "entries": entries, "path": docker_files.normalize_path(path)}
    if op in ("read", "download"):
        limit = docker_files.MAX_EDIT_BYTES if op == "read" else docker_files.MAX_DOWNLOAD_BYTES
        status, stdout, stderr = await run_binary(
            machine, secret, timeout, docker_files.build_read_command(target, path, limit + 4096),
            run_timeout_seconds=300,
        )
        found = docker_files.first_file(stdout)
        if found is None:
            if len(stdout) > limit:
                return {"ok": False, "error": "too_large"}
            return {"ok": False, "error": stderr.strip()[-300:] or "Not a readable file."}
        if len(found.content) > limit:
            return {"ok": False, "error": "too_large"}
        return {
            "ok": True,
            "name": found.name,
            "mode": found.mode,
            "uid": found.uid,
            "gid": found.gid,
            "size": len(found.content),
            "data_b64": base64.b64encode(found.content).decode(),
            "status": status,
        }
    if op == "write":
        content = base64.b64decode(data_b64.encode(), validate=True)
        if len(content) > docker_files.MAX_UPLOAD_BYTES:
            return {"ok": False, "error": "too_large"}
        normalized = docker_files.normalize_path(path)
        directory, base = normalized.rsplit("/", 1)
        base = filename or base
        mode, uid, gid = 0o644, 0, 0
        # A file being replaced keeps its owner and mode.
        _status, head, _stderr = await run_binary(
            machine,
            secret,
            timeout,
            docker_files.build_read_command(
                target, (directory or "") + "/" + base, docker_files.HEADER_BYTES - 1
            ),
        )
        owner = docker_files.first_member_owner(head)
        if owner is not None:
            mode, uid, gid = owner
        tar = docker_files.build_tar(base, content, mode=mode, uid=uid, gid=gid)
        status, _stdout, stderr = await run_binary(
            machine, secret, timeout, docker_files.build_write_command(target, directory or "/"),
            stdin=tar, run_timeout_seconds=300,
        )
        if status != 0:
            return {"ok": False, "error": stderr.strip()[-300:] or "Could not write the file."}
        return {"ok": True}
    if op in ("delete", "mkdir"):
        command = (
            docker_files.build_delete_command(target, path)
            if op == "delete"
            else docker_files.build_mkdir_command(target, path)
        )
        output = await run_script(machine, secret, timeout, command)
        if "@@DC_DONE" not in output.output:
            return {"ok": False, "error": output.output.strip()[-300:] or "The change failed."}
        return {"ok": True}
    return {"ok": False, "error": f"Unknown operation {op!r}."}


@celery_app.task(name="app.tasks.docker_jobs.docker_files", time_limit=_SHORT_TASK_TIME_LIMIT)
def docker_files_task(
    machine_id: str,
    op: str,
    kind: str,
    name: str,
    path: str,
    data_b64: str = "",
    filename: str = "",
) -> dict[str, Any]:
    return asyncio.run(_docker_files(machine_id, op, kind, name, path, data_b64, filename))


# --- Git stacks: auto-sync -----------------------------------------------------


async def queue_stack_deploy(
    session: AsyncSession,
    stack: DockerStack,
    *,
    started_by: str,
    pull: bool = True,
) -> DockerJob | None:
    """Create and queue a deploy job for `stack` unless one is already
    waiting or running. Commits."""
    if await docker_jobs.active_job(
        session, stack.machine_id, DockerJobKind.STACK_DEPLOY, stack.name
    ):
        return None
    job = DockerJob(
        machine_id=stack.machine_id,
        kind=DockerJobKind.STACK_DEPLOY,
        target=stack.name,
        params={"pull": pull},
        started_by=started_by,
        ref_id=stack.id,
    )
    session.add(job)
    await session.commit()
    run_docker_job.delay(str(job.id))
    return job


async def _sync_git_stack(stack_id: str, *, started_by: str) -> dict[str, Any]:
    """Deploy a Git stack when its branch has a commit that is not deployed
    (the auto-sync poll; a webhook deploys without asking)."""
    async with db_session.AsyncSessionLocal() as session:
        stack = await session.get(DockerStack, uuid.UUID(stack_id))
        if stack is None or stack.source != StackSource.GIT:
            return {"ok": False, "error": "Not a Git stack."}
        try:
            machine, secret, timeout = await _machine_and_secret(session, str(stack.machine_id))
            output = await run_script(
                machine,
                secret,
                timeout,
                build_remote_head_command(docker_stacks.git_source(stack)),
                run_timeout_seconds=120,
            )
        except _READ_ERRORS as exc:
            stack.last_checked_at = datetime.now(UTC)
            await session.commit()
            return _error(exc)
        head = parse_commit(output.output)
        stack.last_checked_at = datetime.now(UTC)
        await session.commit()
        if head is None:
            return {"ok": False, "error": output.output.strip()[-300:] or "No such branch."}
        if head == stack.deployed_commit and not docker_stacks.is_changed(stack):
            return {"ok": True, "deployed": False, "commit": head}
        try:
            await docker_jobs.check_project(session, machine, stack.name)
        except docker_jobs.ProtectedError:
            return {"ok": False, "error": docker_jobs.PROTECTED_MESSAGE}
        job = await queue_stack_deploy(session, stack, started_by=started_by)
        return {"ok": True, "deployed": job is not None, "commit": head}


@celery_app.task(name="app.tasks.docker_jobs.sync_git_stack", time_limit=_SHORT_TASK_TIME_LIMIT)
def sync_git_stack(stack_id: str, started_by: str = "Git auto-sync (automatic)") -> dict[str, Any]:
    return asyncio.run(_sync_git_stack(stack_id, started_by=started_by))


async def _poll_git_stacks() -> int:
    """Every few minutes: one `sync_git_stack` per Git stack with auto-sync
    on, never awaited inline."""
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(
            select(DockerStack.id)
            .join(Machine, Machine.id == DockerStack.machine_id)
            .where(
                DockerStack.source == StackSource.GIT,
                DockerStack.auto_sync.is_(True),
                Machine.is_active,
            )
        )
        ids = [row[0] for row in result.all()]
    for stack_id in ids:
        sync_git_stack.delay(str(stack_id))
    return len(ids)


@celery_app.task(name="app.tasks.docker_jobs.poll_git_stacks")
def poll_git_stacks() -> int:
    return asyncio.run(_poll_git_stacks())


__all__ = [
    "STACKS_DIR",
    "docker_backup_snapshots",
    "docker_compose_file",
    "docker_files_task",
    "docker_inventory",
    "poll_git_stacks",
    "purge_old_docker_jobs",
    "queue_stack_deploy",
    "reconcile_docker_jobs",
    "resume_docker_job",
    "run_docker_job",
    "sync_git_stack",
]
