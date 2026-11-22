"""Request body for snoozing one health problem (`app.services.machine_health`)."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.services import machine_health


class HealthSnoozeRequest(BaseModel):
    # `Finding.key` as GET /api/v1/machines/{id}/health lists it.
    key: str = Field(min_length=1, max_length=255)
    # None = until the problem is gone.
    hours: int | None = Field(default=None, ge=1, le=machine_health.MAX_SNOOZE_HOURS)
    note: str | None = Field(default=None, max_length=500)
