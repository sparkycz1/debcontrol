"""Registers the schedulable actions that exist today.

`register_builtin_actions()` is called from `app.main` at import time (so the
web UI's "New scheduled task" form has something to list), from
`app.scheduling.jobs` at import time, and again from each forked Celery
worker child (`app.tasks.celery_app`'s `worker_process_init` handler, so a
child that inherited an empty registry still has one) — it's idempotent, so
calling it from all three is harmless.

To make a new feature schedulable: write an `ActionRunFunc` (reusing
`app.services.machine_actions` where it fits) and add one
`register_action(ScheduledActionSpec(...))` call below. That's the whole
integration surface — the schedule form, validation, and the scheduler tick
all read from the registry, not from a hardcoded list of actions.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_update_run import UpgradeStrategy
from app.scheduling.actions import (
    ActionRunResult,
    ScheduledActionParam,
    ScheduledActionSpec,
    get_action,
    register_action,
)
from app.services.machine_actions import (
    send_power_to_machines,
    trigger_check_updates,
    trigger_updates,
)
from app.ssh.power import PowerAction


async def _run_system_update(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    strategy = UpgradeStrategy(params.get("strategy") or UpgradeStrategy.DIST_UPGRADE.value)
    _batch_id, skipped = await trigger_updates(db, machines, strategy)
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


async def _run_check_updates(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    skipped = await trigger_check_updates(machines)
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


async def _run_reboot(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    skipped = await send_power_to_machines(machines, PowerAction.REBOOT)
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


async def _run_shutdown(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    skipped = await send_power_to_machines(machines, PowerAction.SHUTDOWN)
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


def register_builtin_actions() -> None:
    if get_action("system_update") is not None:
        return  # already registered — safe to call from multiple entry points

    register_action(
        ScheduledActionSpec(
            key="system_update",
            label="System update",
            description=(
                "apt-get update, then dist-upgrade or full-upgrade, then "
                "autoremove/autoclean — same as the manual System updates panel."
            ),
            params=[
                ScheduledActionParam(
                    key="strategy",
                    label="Upgrade strategy",
                    choices=[
                        (UpgradeStrategy.DIST_UPGRADE.value, "dist-upgrade"),
                        (UpgradeStrategy.FULL_UPGRADE.value, "full-upgrade"),
                    ],
                    default=UpgradeStrategy.DIST_UPGRADE.value,
                )
            ],
            run=_run_system_update,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="check_updates",
            label="Check for updates",
            description="Dry run — counts available updates without installing anything.",
            run=_run_check_updates,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="reboot",
            label="Reboot",
            description="Sends `shutdown -r now` to every targeted machine.",
            run=_run_reboot,
            destructive=True,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="shutdown",
            label="Shut down",
            description=(
                "Sends `shutdown -h now`. The machine stays off until someone "
                "powers it back on — there's no scheduled \"power on\"."
            ),
            run=_run_shutdown,
            destructive=True,
        )
    )
