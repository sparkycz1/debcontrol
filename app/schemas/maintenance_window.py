"""Validation for creating/editing a `MaintenanceWindow` — shared by the
web form (`app/web/routes/maintenance.py`) and the REST API
(`app/web/routes/api_v1_notifications.py`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field, model_validator

# A window is for planned work, not a way to switch alerting off for good.
MAX_WINDOW_DURATION = timedelta(days=31)


class MaintenanceWindowSave(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    reason: str | None = Field(default=None, max_length=2000)
    # A naive value is taken as UTC.
    starts_at: datetime
    ends_at: datetime
    all_machines: bool = False
    pause_scheduled_tasks: bool = False
    machine_group_ids: list[uuid.UUID] = Field(default_factory=list)
    machine_ids: list[uuid.UUID] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> MaintenanceWindowSave:
        self.name = self.name.strip()
        self.reason = (self.reason or "").strip() or None
        if self.starts_at.tzinfo is None:
            self.starts_at = self.starts_at.replace(tzinfo=UTC)
        if self.ends_at.tzinfo is None:
            self.ends_at = self.ends_at.replace(tzinfo=UTC)
        if not self.name:
            raise ValueError("A maintenance window needs a name.")
        if self.ends_at <= self.starts_at:
            raise ValueError("The window must end after it starts.")
        if self.ends_at - self.starts_at > MAX_WINDOW_DURATION:
            raise ValueError("A maintenance window can last at most 31 days.")
        if not self.all_machines and not self.machine_group_ids and not self.machine_ids:
            raise ValueError("Pick all machines, or at least one machine group or machine.")
        return self
