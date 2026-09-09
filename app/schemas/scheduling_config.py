"""Pydantic schemas for exporting/importing scheduled-task *configuration*
— config-as-code for Scheduling, same convenience `app.schemas.machine_config`
gives machines/groups and `app.schemas.role_config` gives roles. Targets are
referenced by name (machine/group), not id, so the export is portable across
deployments — see `app.services.scheduling_config` for how those names get
resolved (and what happens when they don't) on import.
"""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, Field, model_validator

from app.db.models.scheduled_task import ScheduleTargetType


class ScheduledTaskExport(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    # Not validated against the action registry here — an export written by
    # a newer debcontrol version, or one with a since-removed action, must
    # still parse; `import_scheduling_config` is what decides whether an
    # unknown action is skippable. Same reasoning as `RoleExport.permissions`.
    action: str = Field(min_length=1, max_length=100)
    action_params: dict[str, str] = Field(default_factory=dict)
    target_type: ScheduleTargetType
    # Names, not ids — portable across deployments. Exactly one of these is
    # set, matching target_type (enforced below), the same shape
    # `ScheduledTask` itself uses for the two FK columns.
    target_machine: str | None = None
    target_group: str | None = None
    cron_expression: str = Field(min_length=1, max_length=100)
    is_enabled: bool = True

    @model_validator(mode="after")
    def _validate_target(self) -> Self:
        if self.target_type == ScheduleTargetType.MACHINE:
            if not self.target_machine:
                raise ValueError('target_machine is required when target_type is "machine".')
            self.target_group = None
        elif self.target_type == ScheduleTargetType.GROUP:
            if not self.target_group:
                raise ValueError('target_group is required when target_type is "group".')
            self.target_machine = None
        else:  # ALL_MACHINES — neither applies.
            self.target_machine = None
            self.target_group = None
        return self


class SchedulingConfigExport(BaseModel):
    scheduled_tasks: list[ScheduledTaskExport] = Field(default_factory=list)
