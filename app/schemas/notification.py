"""Pydantic schemas for the Notifications forms (`app/web/routes/notifications.py`)."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.db.models.notification_rule import NotificationEventType


class NotificationRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    enabled: bool = True
    event_types: list[str] = Field(default_factory=list)

    @field_validator("event_types")
    @classmethod
    def _validate_event_types(cls, value: list[str]) -> list[str]:
        parsed: list[str] = []
        for raw in value:
            try:
                parsed.append(NotificationEventType(raw).value)
            except ValueError:
                raise ValueError(f'Unknown event type "{raw}".') from None
        if not parsed:
            raise ValueError("Choose at least one event to notify on.")
        # De-duplicate, preserving order — a rule submitted twice for the
        # same event (unlikely from the checkbox UI, always possible from
        # the API) should behave the same as listing it once.
        return list(dict.fromkeys(parsed))


class UserGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)


class NotificationTemplateUpdate(BaseModel):
    subject: str = Field(min_length=1, max_length=500)
    body: str = Field(min_length=1, max_length=4000)
