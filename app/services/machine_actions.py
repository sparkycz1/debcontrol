"""Shared logic for triggering an action against a batch of machines.

Extracted out of the machine-groups routes so the exact same code path is
used whether the trigger comes from a human clicking a button (per-machine,
per-group, or "All machines") or from `app.scheduling` firing a cron-like
scheduled task. Takes the arq redis pool directly (not a `Request`) so it
works equally from an HTTP request handler and from inside a background job.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpgradeStrategy
from app.ssh.power import PowerAction


async def trigger_updates(
    db: AsyncSession, redis: Any, machines: list[Machine], strategy: UpgradeStrategy
) -> tuple[uuid.UUID, int]:
    """Create one `MachineUpdateRun` per eligible machine (must have a pinned
    host key) under a shared batch id, commit, then enqueue a job for each.
    Returns (batch_id, skipped_count)."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    batch_id = uuid.uuid4()
    runs = [
        MachineUpdateRun(machine_id=m.id, strategy=strategy, batch_id=batch_id) for m in eligible
    ]
    db.add_all(runs)
    await db.commit()

    # Enqueue only after commit — the worker (a separate process) must be
    # able to find the row the moment it picks the job up.
    for run in runs:
        await redis.enqueue_job("run_machine_update", str(run.id))

    return batch_id, len(machines) - len(eligible)


async def trigger_check_updates(redis: Any, machines: list[Machine]) -> int:
    """Enqueue a `check_machine_updates` job for every eligible (pinned)
    machine. No batch tracking — unlike an actual update run, there's
    nothing meaningful to show on a results page; counts land on each
    machine's own record as each check finishes. Returns skipped count."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    for machine in eligible:
        await redis.enqueue_job("check_machine_updates", str(machine.id))
    return len(machines) - len(eligible)


async def send_power_to_machines(redis: Any, machines: list[Machine], action: PowerAction) -> int:
    """Enqueue a `send_machine_power_command` job for every eligible
    (pinned) machine. Returns skipped count."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    for machine in eligible:
        await redis.enqueue_job("send_machine_power_command", str(machine.id), action.value)
    return len(machines) - len(eligible)
