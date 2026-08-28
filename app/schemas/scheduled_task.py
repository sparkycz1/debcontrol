"""Pydantic schemas for scheduled-task forms."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.db.models.scheduled_task import ScheduleTargetType
from app.scheduling.actions import get_action
from app.scheduling.cron import validate_cron_expression


class ScheduledTaskCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    action: str = Field(min_length=1, max_length=100)
    action_params: dict[str, str] = Field(default_factory=dict)
    target_type: ScheduleTargetType
    target_machine_id: uuid.UUID | None = None
    target_group_id: uuid.UUID | None = None
    cron_expression: str = Field(min_length=1, max_length=100)
    is_enabled: bool = True

    @field_validator("action")
    @classmethod
    def _validate_action(cls, value: str) -> str:
        if get_action(value) is None:
            raise ValueError(f'Unknown action "{value}".')
        return value

    @field_validator("cron_expression")
    @classmethod
    def _validate_cron(cls, value: str) -> str:
        stripped = value.strip()
        validate_cron_expression(stripped)
        return stripped

    @model_validator(mode="after")
    def _validate_target(self) -> Self:
        if self.target_type == ScheduleTargetType.MACHINE:
            if self.target_machine_id is None:
                raise ValueError("Pick a machine for a machine-targeted schedule.")
            self.target_group_id = None
        elif self.target_type == ScheduleTargetType.GROUP:
            if self.target_group_id is None:
                raise ValueError("Pick a group for a group-targeted schedule.")
            self.target_machine_id = None
        else:  # ALL_MACHINES — neither id applies.
            self.target_machine_id = None
            self.target_group_id = None
        return self


class ScheduledTaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    action: str
    action_params: dict[str, str] | None
    target_type: ScheduleTargetType
    target_machine_id: uuid.UUID | None
    target_group_id: uuid.UUID | None
    cron_expression: str
    is_enabled: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_run_summary: str | None
    created_at: datetime
    updated_at: datetime
