"""Update batches — the runs one "run update" on several machines created
together (`MachineUpdateRun.batch_id`, see
`app.services.machine_actions.trigger_updates`). Shared by the batch pages
(`app/web/routes/machine_groups.py`), a run's own page
(`app/web/routes/machines_updates.py`) and the REST API.

A batch is an ad-hoc set of machines, so it can straddle an account's
scope (an unrestricted admin's "All machines" run covers everything).
Everything here returns only the runs on machines the account can see.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.machine import Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.user import User
from app.services.access_scope import machines_visible_to

# How many batches the "recent batches" page lists.
RECENT_BATCH_LIMIT = 50


@dataclass(frozen=True)
class BatchCounts:
    total: int
    pending: int
    running: int
    succeeded: int
    failed: int

    @property
    def unfinished(self) -> int:
        return self.pending + self.running

    def as_dict(self) -> dict[str, int]:
        return {
            "total": self.total,
            "pending": self.pending,
            "running": self.running,
            "succeeded": self.succeeded,
            "failed": self.failed,
        }


@dataclass(frozen=True)
class BatchSummary:
    batch_id: uuid.UUID
    started_at: datetime
    strategy: UpgradeStrategy
    counts: BatchCounts


def count_runs(runs: list[MachineUpdateRun]) -> BatchCounts:
    by_status = dict.fromkeys(UpdateRunStatus, 0)
    for run in runs:
        by_status[run.status] += 1
    return BatchCounts(
        total=len(runs),
        pending=by_status[UpdateRunStatus.PENDING],
        running=by_status[UpdateRunStatus.RUNNING],
        succeeded=by_status[UpdateRunStatus.SUCCEEDED],
        failed=by_status[UpdateRunStatus.FAILED],
    )


async def visible_batch_runs(
    db: AsyncSession, user: User, batch_id: uuid.UUID
) -> list[MachineUpdateRun]:
    """One batch's runs on the machines `user` can see, in machine-name
    order (the order a rolling batch works through them)."""
    visible_ids = (await machines_visible_to(db, user)).with_only_columns(Machine.id)
    result = await db.execute(
        select(MachineUpdateRun)
        .options(selectinload(MachineUpdateRun.machine))
        .where(
            MachineUpdateRun.batch_id == batch_id,
            MachineUpdateRun.machine_id.in_(visible_ids),
        )
        .order_by(MachineUpdateRun.created_at)
    )
    runs = list(result.scalars().all())
    runs.sort(key=lambda run: run.machine.name.lower())
    return runs


async def recent_batches(
    db: AsyncSession, user: User, limit: int = RECENT_BATCH_LIMIT
) -> list[BatchSummary]:
    """The newest batches of more than one machine, with how their runs
    stand. Two queries whatever the number of batches: which batches, then
    the status counts of exactly those."""
    visible_ids = (await machines_visible_to(db, user)).with_only_columns(Machine.id)
    scoped = (
        MachineUpdateRun.batch_id.is_not(None),
        MachineUpdateRun.machine_id.in_(visible_ids),
    )
    started = func.min(MachineUpdateRun.created_at)
    newest = await db.execute(
        select(MachineUpdateRun.batch_id, started, func.min(MachineUpdateRun.strategy))
        .where(*scoped)
        .group_by(MachineUpdateRun.batch_id)
        .having(func.count() > 1)
        .order_by(started.desc())
        .limit(limit)
    )
    rows = list(newest.all())
    if not rows:
        return []
    batch_ids = [row[0] for row in rows]
    counted = await db.execute(
        select(MachineUpdateRun.batch_id, MachineUpdateRun.status, func.count())
        .where(*scoped, MachineUpdateRun.batch_id.in_(batch_ids))
        .group_by(MachineUpdateRun.batch_id, MachineUpdateRun.status)
    )
    per_batch: dict[uuid.UUID, dict[UpdateRunStatus, int]] = {}
    for batch_id, status, count in counted.all():
        if batch_id is not None:
            per_batch.setdefault(batch_id, {})[status] = count
    summaries = []
    for batch_id, started_at, strategy in rows:
        if batch_id is None:  # ruled out by the query; narrows the type
            continue
        counts = per_batch.get(batch_id, {})
        summaries.append(
            BatchSummary(
                batch_id=batch_id,
                started_at=started_at,
                strategy=UpgradeStrategy(strategy),
                counts=BatchCounts(
                    total=sum(counts.values()),
                    pending=counts.get(UpdateRunStatus.PENDING, 0),
                    running=counts.get(UpdateRunStatus.RUNNING, 0),
                    succeeded=counts.get(UpdateRunStatus.SUCCEEDED, 0),
                    failed=counts.get(UpdateRunStatus.FAILED, 0),
                ),
            )
        )
    return summaries


class BatchNotFinishedError(Exception):
    """The batch still has runs waiting or running."""


class NothingFailedError(Exception):
    """No run of the batch failed (on a machine the account can see)."""


async def retry_failed(db: AsyncSession, user: User, batch_id: uuid.UUID) -> tuple[uuid.UUID, int]:
    """Start a new batch on the machines whose run in `batch_id` failed —
    same strategy, same reboot choice, rolling again if the first one was
    (a rolling batch that stopped marked everything after the failure as
    failed too, so those are included). Returns what `trigger_updates`
    does: (the new batch id, machines skipped for having no pinned key).

    Raises `LookupError` for a batch the account sees nothing of."""
    # Imported here: `machine_actions` pulls in the Celery tasks.
    from app.services.machine_actions import trigger_updates

    runs = await visible_batch_runs(db, user, batch_id)
    if not runs:
        raise LookupError(batch_id)
    if count_runs(runs).unfinished:
        raise BatchNotFinishedError(batch_id)
    failed = [run for run in runs if run.status == UpdateRunStatus.FAILED]
    if not failed:
        raise NothingFailedError(batch_id)
    return await trigger_updates(
        db,
        [run.machine for run in failed],
        failed[0].strategy,
        reboot_if_required=any(run.reboot_if_required for run in failed),
        snapshot_before=any(run.snapshot_before for run in failed),
        rolling=any(run.rollout_position is not None for run in runs),
    )
