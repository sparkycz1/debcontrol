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
from app.db.models.role import Permission
from app.scheduling.actions import (
    ActionRunResult,
    ScheduledActionParam,
    ScheduledActionSpec,
    get_action,
    register_action,
)
from app.services.machine_actions import (
    run_custom_command_on_machines,
    send_power_to_machines,
    trigger_check_updates,
    trigger_facts_refresh,
    trigger_monitoring_sample,
    trigger_updates,
)
from app.ssh.power import PowerAction


async def _run_system_update(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    strategy = UpgradeStrategy(params.get("strategy") or UpgradeStrategy.DIST_UPGRADE.value)
    _batch_id, skipped = await trigger_updates(
        db,
        machines,
        strategy,
        reboot_if_required=params.get("reboot") == "if_required",
        rolling=params.get("rollout") == "one_by_one",
    )
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


async def _run_check_updates(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    skipped = await trigger_check_updates(machines)
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


async def _run_force_facts_refresh(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    skipped = await trigger_facts_refresh(machines)
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


async def _run_force_monitoring_sample(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    skipped = await trigger_monitoring_sample(machines)
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


async def _run_custom_command(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    command = params.get("command", "").strip()
    if not command:
        return ActionRunResult(attempted=0, skipped=len(machines))
    skipped = await run_custom_command_on_machines(machines, command)
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


def register_builtin_actions() -> None:
    if get_action("system_update") is not None:
        return  # already registered — safe to call from multiple entry points

    register_action(
        ScheduledActionSpec(
            key="system_update",
            label="System update",
            description=(
                "apt-get update, then full-upgrade, upgrade or only the security "
                "updates, then autoremove/autoclean — same as the manual System "
                "updates panel."
            ),
            params=[
                ScheduledActionParam(
                    key="strategy",
                    label="Upgrade strategy",
                    choices=[
                        (UpgradeStrategy.FULL_UPGRADE.value, "full-upgrade"),
                        (UpgradeStrategy.UPGRADE.value, "upgrade (safe)"),
                        (UpgradeStrategy.SECURITY.value, "security updates only"),
                        # Kept so a task saved with it still edits cleanly —
                        # the same thing as full-upgrade.
                        (UpgradeStrategy.DIST_UPGRADE.value, "dist-upgrade"),
                    ],
                    default=UpgradeStrategy.FULL_UPGRADE.value,
                ),
                ScheduledActionParam(
                    key="reboot",
                    label="Reboot afterwards",
                    choices=[
                        ("never", "Never"),
                        ("if_required", "Only if the update needs it"),
                    ],
                    default="never",
                ),
                ScheduledActionParam(
                    key="rollout",
                    label="Machines",
                    choices=[
                        ("all_at_once", "All at once"),
                        ("one_by_one", "One at a time, next only once the previous is back"),
                    ],
                    default="all_at_once",
                ),
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
            key="force_facts_refresh",
            label="Force facts/packages/services refresh now",
            description=(
                "Enqueues the same four checks a machine's own \"Refresh now\" "
                "buttons do (facts, packages, services, readiness) right away, "
                "instead of waiting out FACTS_REFRESH_INTERVAL_SECONDS — for "
                "verifying a fix or debugging without waiting."
            ),
            run=_run_force_facts_refresh,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="force_monitoring_sample",
            label="Force monitoring sample now",
            description=(
                "Takes one CPU/RAM/disk/failed-services Monitoring-tab sample "
                "right away, instead of waiting out MONITORING_INTERVAL_SECONDS."
            ),
            run=_run_force_monitoring_sample,
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
    register_action(
        ScheduledActionSpec(
            key="run_command",
            label="Run command",
            description=(
                "Runs a shell command on each targeted machine, as that machine's "
                "own configured SSH user — the account needs whatever permission "
                "the command itself requires (e.g. its own sudo rule for a "
                "privileged command); nothing extra is granted for this."
            ),
            params=[
                ScheduledActionParam(
                    key="command",
                    label="Command",
                    default="",
                    param_type="text",
                    placeholder="apt-get clean",
                )
            ],
            run=_run_custom_command,
            destructive=True,
            # Creating/editing a task with this action needs the same
            # permission running an ad-hoc command manually already needs
            # everywhere else in this app (the interactive terminal, the AI
            # assistant's confirm step) — see app.web.routes.scheduling.
            extra_permission=Permission.ACTION_TERMINAL,
        )
    )
