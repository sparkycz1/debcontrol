"""Background jobs that evaluate and fire scheduled tasks.

`run_due_scheduled_tasks` runs on a fixed one-minute cron (same shape as
`app.tasks.jobs.ping_all_machines`) — cron expressions are minute-grained
anyway, so a fixed per-minute tick is simpler than a configurable interval
and needs no new setting. It only enqueues; it never runs an action inline,
for the same reason every other fan-out job in this app doesn't — one very
large group could otherwise make the tick itself run long.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.db.models.scheduled_task import ScheduledTask
from app.db.session import AsyncSessionLocal
from app.scheduling.actions import get_action
from app.scheduling.builtin_actions import register_builtin_actions
from app.scheduling.cron import compute_next_run
from app.scheduling.targets import resolve_target_machines

logger = logging.getLogger(__name__)

# Registering here too (as well as in app.main) covers running just the
# worker process without ever importing app.main.
register_builtin_actions()


async def run_due_scheduled_tasks(ctx: dict[str, Any]) -> None:
    """Every enabled task whose `next_run_at` has passed gets a
    `run_scheduled_task` job enqueued, and its `next_run_at` is advanced
    immediately (before the job actually runs) — so a slow-running action
    can't cause this same task to be re-enqueued on the next tick before it
    has even started."""
    redis = ctx["redis"]
    now = datetime.now(UTC)

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ScheduledTask).where(
                ScheduledTask.is_enabled, ScheduledTask.next_run_at <= now
            )
        )
        due = list(result.scalars().all())
        if not due:
            return

        for task in due:
            await redis.enqueue_job("run_scheduled_task", str(task.id))
            try:
                task.next_run_at = compute_next_run(task.cron_expression, now)
            except ValueError:
                # Shouldn't happen — expressions are validated on save — but
                # don't let a bad stored expression wedge this task into
                # firing every minute forever if it ever does.
                logger.exception(
                    "Disabling scheduled task %s: invalid cron expression %r",
                    task.id,
                    task.cron_expression,
                )
                task.is_enabled = False

        await session.commit()


async def run_scheduled_task(ctx: dict[str, Any], task_id: str) -> dict[str, Any]:
    """Execute one scheduled task: resolve its current target machines and
    hand them to its action's `run` function (see `app.scheduling.actions`).
    Records only a short summary, not a full run log — the underlying
    action's own job (e.g. `MachineUpdateRun`) already records what
    actually happened on each machine."""
    async with AsyncSessionLocal() as session:
        task = await session.get(ScheduledTask, uuid.UUID(task_id))
        if task is None:
            return {"ok": False, "error": "Scheduled task not found."}

        action = get_action(task.action)
        if action is None:
            task.last_run_at = datetime.now(UTC)
            task.last_run_summary = f'Unknown action "{task.action}" — nothing was run.'
            await session.commit()
            logger.warning("run_scheduled_task(%s): %s", task.id, task.last_run_summary)
            return {"ok": False, "error": task.last_run_summary}

        machines = await resolve_target_machines(session, task)
        result = await action.run(session, ctx["redis"], machines, task.action_params or {})

        summary = f"Triggered for {result.attempted} machine(s)."
        if result.skipped:
            summary = (
                f"Triggered for {result.attempted} machine(s), "
                f"{result.skipped} skipped (no pinned host key)."
            )
        task.last_run_at = datetime.now(UTC)
        task.last_run_summary = summary
        await session.commit()

        return {"ok": True, "attempted": result.attempted, "skipped": result.skipped}
