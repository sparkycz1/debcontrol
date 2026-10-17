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
    ActionRunFunc,
    ActionRunResult,
    ScheduledActionParam,
    ScheduledActionSpec,
    get_action,
    register_action,
)
from app.services import docker_actions
from app.services.docker_gate import GATES
from app.services.machine_actions import (
    run_custom_command_on_machines,
    send_power_to_machines,
    trigger_check_updates,
    trigger_facts_refresh,
    trigger_monitoring_sample,
    trigger_security_audits,
    trigger_updates,
    wake_machines,
)
from app.ssh.docker_prune import PruneOptions
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
        snapshot_before=params.get("snapshot") == "proxmox",
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


async def _run_wake(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    skipped = await wake_machines(machines)
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


async def _run_security_audit(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    _audits, skipped = await trigger_security_audits(
        db,
        machines,
        started_by="schedule",
    )
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


async def _run_custom_command(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    command = params.get("command", "").strip()
    if not command:
        return ActionRunResult(attempted=0, skipped=len(machines))
    skipped = await run_custom_command_on_machines(machines, command)
    return ActionRunResult(attempted=len(machines) - skipped, skipped=skipped)


async def _run_docker_update(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    # "every", not "all": the task form keeps the bare value "all" for its
    # own "All machines" target option.
    scope = params.get("docker_scope") or "auto"
    scope = "all" if scope == "every" else scope
    if scope not in docker_actions.UPDATE_SCOPES:
        scope = "auto"
    gate = params.get("docker_gate") or "setting"
    attempted, skipped = await docker_actions.trigger_container_updates(
        db,
        machines,
        scope=scope,
        gate=gate if gate in GATES else None,
        started_by="schedule",
    )
    return ActionRunResult(attempted=attempted, skipped=skipped)


async def _run_docker_scan(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    scope = params.get("docker_scan_scope") or "in_use"
    scope = "all" if scope == "every" else scope
    if scope not in docker_actions.SCAN_SCOPES:
        scope = "in_use"
    attempted, skipped = await docker_actions.trigger_scans(
        db, machines, scope=scope, started_by="schedule"
    )
    return ActionRunResult(attempted=attempted, skipped=skipped)


# What a scheduled clean-up removes. Named volumes (data) never: removing
# them takes a person typing the machine's name on the Docker tab.
_PRUNE_LEVELS = {
    "safe": PruneOptions(containers=True, images=True, networks=True, build_cache=True),
    "images": PruneOptions(
        containers=True, images=True, all_images=True, networks=True, build_cache=True
    ),
    "volumes": PruneOptions(
        containers=True, images=True, networks=True, volumes=True, build_cache=True
    ),
}


async def _run_docker_prune(
    db: AsyncSession, machines: list[Machine], params: dict[str, str]
) -> ActionRunResult:
    options = _PRUNE_LEVELS.get(params.get("docker_prune_level") or "", _PRUNE_LEVELS["safe"])
    attempted, skipped = await docker_actions.trigger_prune(
        db, machines, options, started_by="schedule"
    )
    return ActionRunResult(attempted=attempted, skipped=skipped)


def _docker_backup_runner(what: str) -> ActionRunFunc:
    async def run(
        db: AsyncSession, machines: list[Machine], params: dict[str, str]
    ) -> ActionRunResult:
        attempted, skipped = await docker_actions.trigger_backups(
            db, machines, what, started_by="schedule"
        )
        return ActionRunResult(attempted=attempted, skipped=skipped)

    return run


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
                ScheduledActionParam(
                    key="snapshot",
                    label="Snapshot first",
                    choices=[
                        ("none", "No"),
                        ("proxmox", "Proxmox snapshot of each machine that is a known guest"),
                    ],
                    default="none",
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
                "powers it back on, or a scheduled \"Wake up\" does."
            ),
            run=_run_shutdown,
            destructive=True,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="wake",
            label="Wake up (Wake-on-LAN)",
            description=(
                "Sends a Wake-on-LAN packet to each machine that is not answering, "
                "through another managed machine on its network. Machines that are "
                "up, or whose network card is not known yet, are skipped."
            ),
            run=_run_wake,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="security_audit",
            label="Security audit",
            description=(
                "Installs or updates Lynis, runs debcontrol's own checks and "
                "`lynis audit system` on each targeted machine and keeps the "
                "results (Security -> Audit). Machines with an audit still "
                "running are skipped."
            ),
            # A task saved before 0.118.0 may still carry an `install`
            # param; it is ignored (Lynis is always installed or updated).
            run=_run_security_audit,
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

    register_action(
        ScheduledActionSpec(
            key="docker_update",
            label="Update Docker containers",
            description=(
                "Pulls each chosen container's newest image and recreates it with "
                "the same settings, one container after another per machine; a "
                "container that doesn't come back up is put back. Optionally "
                "stopped by a vulnerability scan of the new image."
            ),
            params=[
                ScheduledActionParam(
                    key="docker_scope",
                    label="Containers",
                    choices=[
                        ("auto", "Those set to update automatically"),
                        ("with_update", "Those the image check found a newer image for"),
                        ("every", "Every container"),
                    ],
                    default="auto",
                ),
                ScheduledActionParam(
                    key="docker_gate",
                    label="Vulnerability gate",
                    choices=[
                        ("setting", "As set for each container"),
                        ("off", "Don't check"),
                        ("critical", "Stop on a critical vulnerability"),
                        ("high", "Stop on a critical or high vulnerability"),
                        ("worse", "Stop when worse than the running image"),
                    ],
                    default="setting",
                ),
            ],
            run=_run_docker_update,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="docker_scan",
            label="Scan Docker images",
            description=(
                "Scans images for vulnerabilities with Trivy and Grype (both pulled "
                "fresh each time, so findings published since the last scan show "
                "up too). Choose which images: those containers use, only those "
                "never scanned, or every image."
            ),
            params=[
                ScheduledActionParam(
                    key="docker_scan_scope",
                    label="Images",
                    choices=[
                        ("in_use", "Images containers use"),
                        ("unscanned", "Images not scanned yet"),
                        ("every", "Every image"),
                    ],
                    default="in_use",
                ),
            ],
            run=_run_docker_scan,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="docker_prune",
            label="Clean up Docker",
            description=(
                "Removes stopped containers, untagged images, unused networks and "
                "the build cache. Named volumes are never removed by a schedule."
            ),
            params=[
                ScheduledActionParam(
                    key="docker_prune_level",
                    label="Also remove",
                    choices=[
                        ("safe", "Nothing more"),
                        ("images", "Every image no container uses"),
                        ("volumes", "Unused anonymous volumes"),
                    ],
                    default="safe",
                ),
            ],
            run=_run_docker_prune,
            destructive=True,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="docker_backup",
            label="Docker backup",
            description="Runs every enabled restic backup of each machine's Docker tab.",
            run=_docker_backup_runner("run"),
        )
    )
    register_action(
        ScheduledActionSpec(
            key="docker_backup_check",
            label="Check Docker backups",
            description="Runs restic check on the repository of every enabled backup.",
            run=_docker_backup_runner("check"),
        )
    )
    register_action(
        ScheduledActionSpec(
            key="docker_backup_prune",
            label="Prune Docker backups",
            description=(
                "Deletes the snapshots each enabled backup's retention doesn't keep "
                "(restic forget --prune). Backups without retention are skipped."
            ),
            run=_docker_backup_runner("forget"),
            destructive=True,
        )
    )
