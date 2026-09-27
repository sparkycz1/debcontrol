"""Pydantic schemas for scheduled-task forms."""

from __future__ import annotations

import uuid
from typing import Self

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.timezones import is_valid_timezone
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
    # IANA name ("Europe/Prague"); None/"" = UTC.
    timezone: str | None = Field(default=None, max_length=64)
    require_maintenance_window: bool = False

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, value: str | None) -> str | None:
        value = (value or "").strip()
        if not value:
            return None
        if not is_valid_timezone(value):
            raise ValueError(f'"{value}" is not a known time zone (e.g. "Europe/Prague").')
        return value

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
