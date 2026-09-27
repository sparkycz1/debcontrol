"""Export/import of scheduled-task *configuration* — config-as-code for
Scheduling, same "one service function, two doors" convention as
`app.services.machine_config` (web route + REST API). Lets an admin version
a fleet's cron schedule in git and replay it onto another debcontrol
instance, the same way machine/group and role config already can.

Targets are resolved by **name**, not id, so an export is portable across
deployments (see `app.schemas.scheduling_config.ScheduledTaskExport`) —
which means, unlike machines/groups, a scheduled task can't just create
whatever it references: a machine or group has to already exist by that
exact name in the destination deployment, or the task is skipped rather
than silently attached to nothing (or worse, to a different, same-named
machine created some other way). Same for `action`: a key this instance's
action registry doesn't know (an export from a newer version, or one using
an action a plugin/fork added) is skipped rather than stored unusable.

A task name is not unique in the data model (`ScheduledTask.name` has no
uniqueness constraint), so unlike machines/roles this import is always
create-only, never conflict-checked — running the same import twice
creates two identical schedules. Deliberate: re-importing after editing
some *other* task in the same file shouldn't require an operator to guess
whether unrelated tasks changed enough to warrant a name comparison. If
that becomes a problem in practice, delete the old ones by hand first.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.timezones import is_valid_timezone
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from app.db.models.user import User
from app.scheduling.actions import get_action
from app.scheduling.cron import compute_next_run, validate_cron_expression
from app.scheduling.targets import target_within_scope
from app.schemas.scheduling_config import ScheduledTaskExport, SchedulingConfigExport


async def export_scheduling_config(db: AsyncSession) -> SchedulingConfigExport:
    """Every `ScheduledTask`, targets resolved to names. Not scoped by
    account — same reasoning as `export_role_config`: reaching this route
    at all already requires `scheduling.view` fleet-wide (there's no
    partial-fleet scheduling view), so there's nothing narrower to filter
    by here the way machines/groups need `access_scope` for."""
    result = await db.execute(
        select(ScheduledTask).order_by(ScheduledTask.name)
    )
    tasks = []
    for task in result.scalars().all():
        target_machine = None
        target_group = None
        if task.target_type == ScheduleTargetType.MACHINE and task.target_machine_id:
            machine = await db.get(Machine, task.target_machine_id)
            target_machine = machine.name if machine else None
        elif task.target_type == ScheduleTargetType.GROUP and task.target_group_id:
            group = await db.get(MachineGroup, task.target_group_id)
            target_group = group.name if group else None

        tasks.append(
            ScheduledTaskExport(
                name=task.name,
                action=task.action,
                action_params={k: str(v) for k, v in (task.action_params or {}).items()},
                target_type=task.target_type,
                target_machine=target_machine,
                target_group=target_group,
                cron_expression=task.cron_expression,
                timezone=task.timezone,
                require_maintenance_window=task.require_maintenance_window,
                is_enabled=task.is_enabled,
            )
        )
    return SchedulingConfigExport(scheduled_tasks=tasks)


@dataclass
class SchedulingImportResult:
    created_tasks: list[str] = field(default_factory=list)
    skipped_tasks: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {"created_tasks": self.created_tasks, "skipped_tasks": self.skipped_tasks}

    def summary(self) -> str:
        summary = f"Imported {len(self.created_tasks)} scheduled task(s)"
        if self.skipped_tasks:
            summary += f", skipped {len(self.skipped_tasks)}"
        return summary


async def import_scheduling_config(
    db: AsyncSession, payload: SchedulingConfigExport, user: User
) -> SchedulingImportResult:
    """Create real `ScheduledTask` rows from `payload`, as `user` — unlike
    machine/role import, a task's target can name something the importing
    account isn't scoped to (a restricted admin's own `scheduling.manage`
    only ever lets them target their own machine groups by hand, same as
    creating one through the form), so every task is checked with the same
    `target_within_scope` the manual create/edit routes use and skipped,
    not silently created, if it falls outside `user`'s scope. See the
    module docstring for why an unresolved target or unknown action is
    skipped rather than partially imported, and why this never
    conflict-checks by name."""
    result = SchedulingImportResult()

    machines_by_name = {
        m.name: m for m in (await db.execute(select(Machine))).scalars().all()
    }
    groups_by_name = {
        g.name: g for g in (await db.execute(select(MachineGroup))).scalars().all()
    }

    for task_export in payload.scheduled_tasks:
        action_spec = get_action(task_export.action)
        if action_spec is None:
            result.skipped_tasks.append(
                {
                    "name": task_export.name,
                    "reason": f'Unknown action "{task_export.action}" on this instance.',
                }
            )
            continue
        if action_spec.extra_permission is not None and not user.has_permission(
            action_spec.extra_permission
        ):
            result.skipped_tasks.append(
                {
                    "name": task_export.name,
                    "reason": (
                        f'The "{action_spec.label}" action also needs the '
                        f'"{action_spec.extra_permission.value}" permission, which your '
                        "account doesn't have."
                    ),
                }
            )
            continue

        try:
            validate_cron_expression(task_export.cron_expression)
            if task_export.timezone and not is_valid_timezone(task_export.timezone):
                raise ValueError(f'unknown time zone "{task_export.timezone}"')
        except ValueError as exc:
            result.skipped_tasks.append({"name": task_export.name, "reason": str(exc)})
            continue

        target_machine_id = None
        target_group_id = None
        if task_export.target_type == ScheduleTargetType.MACHINE:
            machine = machines_by_name.get(task_export.target_machine or "")
            if machine is None:
                result.skipped_tasks.append(
                    {
                        "name": task_export.name,
                        "reason": (
                            f'No machine named "{task_export.target_machine}" '
                            "on this instance."
                        ),
                    }
                )
                continue
            target_machine_id = machine.id
        elif task_export.target_type == ScheduleTargetType.GROUP:
            group = groups_by_name.get(task_export.target_group or "")
            if group is None:
                result.skipped_tasks.append(
                    {
                        "name": task_export.name,
                        "reason": (
                            f'No group named "{task_export.target_group}" on this instance.'
                        ),
                    }
                )
                continue
            target_group_id = group.id

        if not await target_within_scope(
            db, user, task_export.target_type, target_machine_id, target_group_id
        ):
            result.skipped_tasks.append(
                {
                    "name": task_export.name,
                    "reason": "Target is outside your account's machine-group scope.",
                }
            )
            continue

        task = ScheduledTask(
            name=task_export.name,
            action=task_export.action,
            action_params=task_export.action_params,
            target_type=task_export.target_type,
            target_machine_id=target_machine_id,
            target_group_id=target_group_id,
            cron_expression=task_export.cron_expression,
            timezone=task_export.timezone or None,
            require_maintenance_window=task_export.require_maintenance_window,
            is_enabled=task_export.is_enabled,
            next_run_at=(
                compute_next_run(task_export.cron_expression, timezone=task_export.timezone or None)
                if task_export.is_enabled
                else None
            ),
        )
        db.add(task)
        result.created_tasks.append(task_export.name)

    await db.commit()
    return result
