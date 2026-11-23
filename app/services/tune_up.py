"""Tune-up ("Komplet", nav: **Health → Tune-up**): every maintenance step
debcontrol can run on a machine, in one go, on one machine or many.

The steps, in the order they run (`STEPS`):

1. `refresh` — facts, packages, services and readiness, so every later
   step works from how the machine is now. If the machine can't be reached
   here, the rest is skipped.
2. `system_update` — `apt-get update`, `full-upgrade`, `autoremove`,
   `autoclean` (and flatpak / snap where installed): an ordinary update
   run (`MachineUpdateRun`), so it shows in the machine's update history,
   with a Proxmox snapshot first when asked.
3. `image_check` — which containers have a newer image, and the Docker
   host check.
4. `docker_update` — every container to the newest image of its tag (a
   container already on it is skipped), each with its own vulnerability
   gate; debcontrol's own containers are left alone.
5. `docker_prune` — `docker system prune -a` without volumes: stopped
   containers, every image no container uses, unused networks, the build
   cache. Data in volumes is never touched.
6. `image_scan` — every image scanned for vulnerabilities (Trivy, Grype).
7. `security_audit` — Lynis and debcontrol's own checks.
8. `final_refresh` — facts, packages, pending updates, a monitoring sample
   and the machine's health, so the pages show the result straight away.
9. `reboot` — only when asked, only when the machine says it needs one,
   and never for debcontrol's own host or the hypervisor under it.

The Docker steps are skipped on a machine without Docker. Steps 2 to 7 and 9
can each be left out (`Options`). A failed step is recorded and the next
one runs; only an unreachable machine stops a run.

**How it runs.** One `TuneUpRun` per machine; a Celery task follows it
step by step (`app.tasks.tune_up`). At most `MAX_PARALLEL` machines run at
once — the rest wait their turn — and debcontrol's own host and the
hypervisor under it go after every other machine of the batch, as with
updates (`app.services.self_host`). Steps that are jobs of their own (the
update run, Docker jobs, the audit) are started through the same code as
their own buttons and appear in their own histories too.

Permission: `action.updates` (the same as each step on its own);
rebooting also needs `action.power`.
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import tune_up as model
from app.db.models.machine import Machine
from app.db.models.tune_up import TuneUpRun
from app.services import self_host

STEPS = (
    "refresh",
    "system_update",
    "image_check",
    "docker_update",
    "docker_prune",
    "image_scan",
    "security_audit",
    "final_refresh",
    "reboot",
)
DOCKER_STEPS = ("image_check", "docker_update", "docker_prune", "image_scan")

# Step statuses.
STEP_PENDING = "pending"
STEP_RUNNING = "running"
STEP_OK = "ok"
STEP_FAILED = "failed"
STEP_SKIPPED = "skipped"
STEP_FINAL = (STEP_OK, STEP_FAILED, STEP_SKIPPED)

# Machines tuned up at once, across every batch. Each run keeps a worker
# busy while it waits for its steps, so this leaves room for the jobs the
# steps themselves start.
MAX_PARALLEL = 4

# A running run whose task has not written for this long has lost it
# (a worker restart); `app.tasks.tune_up.reconcile` takes it up again.
STALE_AFTER = timedelta(minutes=10)
# A run queued this long ago that never started lost its message.
REQUEUE_AFTER = timedelta(minutes=30)

RECENT_BATCHES = 20


@dataclass(frozen=True)
class Options:
    """What to include. Everything but the snapshot and the reboot by
    default."""

    system_update: bool = True
    snapshot: bool = False
    docker_update: bool = True
    docker_prune: bool = True
    image_scan: bool = True
    security_audit: bool = True
    reboot: bool = False

    def as_dict(self) -> dict[str, bool]:
        return {
            "system_update": self.system_update,
            "snapshot": self.snapshot,
            "docker_update": self.docker_update,
            "docker_prune": self.docker_prune,
            "image_scan": self.image_scan,
            "security_audit": self.security_audit,
            "reboot": self.reboot,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Options:
        data = data or {}
        defaults = cls().as_dict()
        return cls(**{key: bool(data.get(key, default)) for key, default in defaults.items()})

    @classmethod
    def from_form(cls, form: Any) -> Options:
        """From a submitted form: a checkbox that is not ticked is not sent."""
        return cls(**{key: form.get(key) in ("1", "on", "true") for key in cls().as_dict()})

    def wanted(self, step: str) -> bool:
        if step in ("refresh", "final_refresh", "image_check"):
            return True
        return bool(self.as_dict().get(step, False))


def plan(options: Options) -> list[dict[str, Any]]:
    """The steps of one run, before it starts."""
    return [
        {
            "key": step,
            "status": STEP_PENDING if options.wanted(step) else STEP_SKIPPED,
            "detail": None if options.wanted(step) else {"code": "not_selected"},
            "ref": {},
            "started_at": None,
            "finished_at": None,
        }
        for step in STEPS
    ]


def overall(steps: list[dict[str, Any]]) -> str:
    """succeeded / failed from the steps of a finished run."""
    return (
        model.FAILED
        if any(step.get("status") == STEP_FAILED for step in steps)
        else model.SUCCEEDED
    )


# --- Starting ----------------------------------------------------------------


async def open_machine_ids(db: AsyncSession, machine_ids: list[uuid.UUID]) -> set[uuid.UUID]:
    if not machine_ids:
        return set()
    result = await db.execute(
        select(TuneUpRun.machine_id).where(
            TuneUpRun.machine_id.in_(machine_ids),
            TuneUpRun.status.in_(model.OPEN_STATUSES),
        )
    )
    return set(result.scalars().all())


async def start(
    db: AsyncSession,
    machines: list[Machine],
    options: Options,
    *,
    started_by: str | None,
) -> tuple[uuid.UUID | None, int]:
    """One run per machine that has a pinned host key and no tune-up
    already open, under one batch id; commit, then queue as many as may run.
    Returns (batch id or None when nothing started, skipped count)."""
    busy = await open_machine_ids(db, [m.id for m in machines])
    eligible = [m for m in machines if m.host_key_fingerprint and m.id not in busy]
    if not eligible:
        return None, len(machines)
    own = await self_host.find(db)
    batch_id = uuid.uuid4()
    steps = plan(options)
    db.add_all(
        TuneUpRun(
            batch_id=batch_id,
            machine_id=m.id,
            status=model.PENDING,
            options=options.as_dict(),
            steps=[dict(step) for step in steps],
            hold_order=own.hold_order(m.id),
            started_by=started_by,
            created_at=datetime.now(UTC),
        )
        for m in sorted(eligible, key=lambda m: m.name.lower())
    )
    await db.commit()
    await kick(db)
    return batch_id, len(machines) - len(eligible)


def _as_aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


async def _held_back(db: AsyncSession, run: TuneUpRun) -> bool:
    """A held run (debcontrol's own host, its hypervisor) waits until every
    run of its batch with a lower hold order is over."""
    if run.hold_order is None:
        return False
    waiting = await db.scalar(
        select(func.count())
        .select_from(TuneUpRun)
        .where(
            TuneUpRun.batch_id == run.batch_id,
            TuneUpRun.id != run.id,
            TuneUpRun.status.in_(model.OPEN_STATUSES),
            (TuneUpRun.hold_order.is_(None)) | (TuneUpRun.hold_order < run.hold_order),
        )
    )
    return bool(waiting)


async def kick(db: AsyncSession) -> int:
    """Queue waiting runs while fewer than `MAX_PARALLEL` are under way.
    Returns how many were queued."""
    # Imported here: the task module imports this one.
    from app.tasks.tune_up import run_tune_up

    busy = await db.scalar(
        select(func.count())
        .select_from(TuneUpRun)
        .where(
            (TuneUpRun.status == model.RUNNING)
            | ((TuneUpRun.status == model.PENDING) & TuneUpRun.queued_at.is_not(None))
        )
    )
    room = MAX_PARALLEL - int(busy or 0)
    if room <= 0:
        return 0
    result = await db.execute(
        select(TuneUpRun)
        .where(TuneUpRun.status == model.PENDING, TuneUpRun.queued_at.is_(None))
        .order_by(TuneUpRun.created_at, TuneUpRun.hold_order.nulls_first(), TuneUpRun.id)
        .limit(200)
    )
    chosen: list[TuneUpRun] = []
    for run in result.scalars().all():
        if len(chosen) >= room:
            break
        if await _held_back(db, run):
            continue
        chosen.append(run)
    now = datetime.now(UTC)
    for run in chosen:
        run.queued_at = now
    await db.commit()
    for run in chosen:
        run_tune_up.delay(str(run.id))
    return len(chosen)


async def cancel_batch(
    db: AsyncSession, batch_id: uuid.UUID, machine_ids: set[uuid.UUID] | None, *, actor: str
) -> int:
    """Stop a batch: waiting runs end at once, a running one after its
    current step. Only the runs of machines in `machine_ids` (None = all)
    the caller may see. Returns how many runs it touched."""
    query = select(TuneUpRun).where(
        TuneUpRun.batch_id == batch_id, TuneUpRun.status.in_(model.OPEN_STATUSES)
    )
    if machine_ids is not None:
        query = query.where(TuneUpRun.machine_id.in_(machine_ids))
    # Fresh rows: a run its task just claimed must not be read as waiting.
    query = query.execution_options(populate_existing=True)
    runs = list((await db.execute(query)).scalars().all())
    now = datetime.now(UTC)
    for run in runs:
        run.cancel_requested_by = actor[:255]
        if run.status == model.PENDING:
            run.status = model.CANCELLED
            run.finished_at = now
            run.steps = [
                {**step, "status": STEP_SKIPPED, "detail": {"code": "cancelled"}}
                if step.get("status") == STEP_PENDING
                else step
                for step in run.steps or []
            ]
    await db.commit()
    return len(runs)


async def claim(db: AsyncSession, run_id: uuid.UUID) -> bool:
    """Pending → running, by whoever gets there first."""
    now = datetime.now(UTC)
    result = await db.execute(
        update(TuneUpRun)
        .where(TuneUpRun.id == run_id, TuneUpRun.status == model.PENDING)
        .values(status=model.RUNNING, started_at=now, heartbeat_at=now)
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return getattr(result, "rowcount", 0) == 1


# --- Reading -----------------------------------------------------------------


@dataclass
class BatchView:
    batch_id: uuid.UUID
    created_at: datetime | None
    started_by: str | None
    runs: list[TuneUpRun] = field(default_factory=list)

    @property
    def counts(self) -> Counter[str]:
        return Counter(run.status for run in self.runs)

    @property
    def open(self) -> bool:
        return any(run.status in model.OPEN_STATUSES for run in self.runs)

    @property
    def status(self) -> str:
        counts = self.counts
        if counts[model.RUNNING] or counts[model.PENDING]:
            return model.RUNNING
        if counts[model.FAILED]:
            return model.FAILED
        if counts[model.CANCELLED] and not counts[model.SUCCEEDED]:
            return model.CANCELLED
        return model.SUCCEEDED

    @property
    def options(self) -> Options:
        return Options.from_dict(self.runs[0].options if self.runs else None)


def _visible(query: Any, machine_ids: set[uuid.UUID] | None) -> Any:
    return query if machine_ids is None else query.where(TuneUpRun.machine_id.in_(machine_ids))


async def recent_batches(
    db: AsyncSession, machine_ids: set[uuid.UUID] | None, limit: int = RECENT_BATCHES
) -> list[BatchView]:
    """The newest batches with a run on a machine the caller may see,
    newest first — each with only those runs."""
    ids_query = _visible(
        select(TuneUpRun.batch_id, func.max(TuneUpRun.created_at).label("at"))
        .group_by(TuneUpRun.batch_id)
        .order_by(func.max(TuneUpRun.created_at).desc())
        .limit(limit),
        machine_ids,
    )
    batch_ids = [row[0] for row in (await db.execute(ids_query)).all()]
    if not batch_ids:
        return []
    runs = await _runs(db, batch_ids, machine_ids)
    views: dict[uuid.UUID, BatchView] = {}
    for run in runs:
        view = views.setdefault(
            run.batch_id, BatchView(run.batch_id, run.created_at, run.started_by)
        )
        view.runs.append(run)
    return [views[b] for b in batch_ids if b in views]


async def batch(
    db: AsyncSession, batch_id: uuid.UUID, machine_ids: set[uuid.UUID] | None
) -> BatchView | None:
    runs = await _runs(db, [batch_id], machine_ids)
    if not runs:
        return None
    return BatchView(batch_id, runs[0].created_at, runs[0].started_by, runs)


async def _runs(
    db: AsyncSession, batch_ids: list[uuid.UUID], machine_ids: set[uuid.UUID] | None
) -> list[TuneUpRun]:
    query = _visible(
        select(TuneUpRun, Machine.name)
        .join(Machine, Machine.id == TuneUpRun.machine_id)
        .where(TuneUpRun.batch_id.in_(batch_ids))
        .order_by(TuneUpRun.hold_order.nulls_first(), Machine.name),
        machine_ids,
    )
    runs: list[TuneUpRun] = []
    for run, name in (await db.execute(query)).all():
        run.machine_name = name
        runs.append(run)
    return runs


async def last_for_machine(db: AsyncSession, machine_id: uuid.UUID) -> TuneUpRun | None:
    return await db.scalar(
        select(TuneUpRun)
        .where(TuneUpRun.machine_id == machine_id)
        .order_by(TuneUpRun.created_at.desc())
        .limit(1)
    )


def current_step(run: TuneUpRun) -> str | None:
    for step in run.steps or []:
        if step.get("status") == STEP_RUNNING:
            return str(step.get("key"))
    return None


def run_dict(run: TuneUpRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "batch_id": str(run.batch_id),
        "machine_id": str(run.machine_id),
        "machine_name": getattr(run, "machine_name", None),
        "status": run.status,
        "error": run.error,
        "steps": [
            {
                "key": step.get("key"),
                "status": step.get("status"),
                "detail": step.get("detail"),
                "started_at": step.get("started_at"),
                "finished_at": step.get("finished_at"),
            }
            for step in run.steps or []
        ],
        "waits_for_rest": run.hold_order is not None,
        "started_by": run.started_by,
        "cancel_requested_by": run.cancel_requested_by,
        "created_at": _iso(run.created_at),
        "started_at": _iso(run.started_at),
        "finished_at": _iso(run.finished_at),
    }


def batch_dict(view: BatchView) -> dict[str, Any]:
    return {
        "batch_id": str(view.batch_id),
        "status": view.status,
        "created_at": _iso(view.created_at),
        "started_by": view.started_by,
        "options": view.options.as_dict(),
        "counts": dict(view.counts),
        "runs": [run_dict(run) for run in view.runs],
    }


def _iso(value: datetime | None) -> str | None:
    value = _as_aware(value)
    return value.isoformat() if value else None
