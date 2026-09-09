"""Shared logic for triggering an action against a batch of machines.

Extracted out of the machine-groups routes so the exact same code path is
used whether the trigger comes from a human clicking a button (per-machine,
per-group, or "All machines") or from `app.scheduling` firing a cron-like
scheduled task.

These take no queue handle of any kind — Celery task objects are just
importable Python objects, so enqueueing is a plain `some_task.delay(...)`
call. That is why this module works unchanged from inside an HTTP request
handler and from inside a background task.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpgradeStrategy
from app.ssh.power import PowerAction
from app.tasks.jobs import (
    check_machine_readiness,
    check_machine_updates,
    refresh_machine_facts,
    refresh_machine_packages,
    refresh_machine_services,
    run_machine_update,
    run_remote_ssh_command,
    sample_machine_monitoring,
    send_machine_power_command,
)


async def trigger_updates(
    db: AsyncSession, machines: list[Machine], strategy: UpgradeStrategy
) -> tuple[uuid.UUID, int]:
    """Create one `MachineUpdateRun` per eligible machine (must have a pinned
    host key) under a shared batch id, commit, then enqueue a task for each.
    Returns (batch_id, skipped_count)."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    batch_id = uuid.uuid4()
    runs = [
        MachineUpdateRun(machine_id=m.id, strategy=strategy, batch_id=batch_id) for m in eligible
    ]
    db.add_all(runs)
    await db.commit()

    # Enqueue only after commit — the worker (a separate process) must be
    # able to find the row the moment it picks the task up.
    for run in runs:
        run_machine_update.delay(str(run.id))

    return batch_id, len(machines) - len(eligible)


async def trigger_check_updates(machines: list[Machine]) -> int:
    """Enqueue a `check_machine_updates` task for every eligible (pinned)
    machine. No batch tracking — unlike an actual update run, there's
    nothing meaningful to show on a results page; counts land on each
    machine's own record as each check finishes. Returns skipped count."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    for machine in eligible:
        check_machine_updates.delay(str(machine.id))
    return len(machines) - len(eligible)


async def trigger_facts_refresh(machines: list[Machine]) -> int:
    """Enqueue the same four tasks a machine's own "Refresh now" buttons
    do (facts, packages, services, readiness) for every eligible (pinned)
    machine — the fleet-wide/on-demand version of the periodic sweep
    Celery Beat already runs on `FACTS_REFRESH_INTERVAL_SECONDS`. For
    debugging/verifying a fix without waiting out that interval — see
    `app.scheduling.builtin_actions`'s "force_facts_refresh" action.
    Returns skipped count."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    for machine in eligible:
        machine_id = str(machine.id)
        refresh_machine_facts.delay(machine_id)
        refresh_machine_packages.delay(machine_id)
        refresh_machine_services.delay(machine_id)
        check_machine_readiness.delay(machine_id)
    return len(machines) - len(eligible)


async def trigger_monitoring_sample(machines: list[Machine]) -> int:
    """Enqueue a `sample_machine_monitoring` task for every eligible
    (pinned) machine — the fleet-wide/on-demand version of the periodic
    sweep Celery Beat already runs on `MONITORING_INTERVAL_SECONDS`, kept
    separate from `trigger_facts_refresh` since it's on its own,
    independently configurable cadence. Returns skipped count."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    for machine in eligible:
        sample_machine_monitoring.delay(str(machine.id))
    return len(machines) - len(eligible)


async def send_power_to_machines(machines: list[Machine], action: PowerAction) -> int:
    """Enqueue a `send_machine_power_command` task for every eligible
    (pinned) machine. Returns skipped count."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    for machine in eligible:
        send_machine_power_command.delay(str(machine.id), action.value)
    return len(machines) - len(eligible)


async def run_custom_command_on_machines(machines: list[Machine], command: str) -> int:
    """Enqueue a `run_remote_ssh_command` task for every eligible (pinned)
    machine — the same task the AI assistant's `run_ssh_command` tool uses
    after its own human-confirmation step. There's no result page here
    (unlike an update run): each task's outcome only lands in that task's
    own Celery result backend entry, same "fire and don't track" shape as
    `trigger_check_updates`/`send_power_to_machines`. Returns skipped
    count. **Callers must independently gate creating/editing a
    `run_command` scheduled task behind `action.terminal`** — this
    function itself performs no authorization, same trust boundary
    `run_remote_ssh_command` itself documents."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    for machine in eligible:
        run_remote_ssh_command.delay(str(machine.id), command)
    return len(machines) - len(eligible)
