"""Pydantic schemas for the Notifications forms (`app/web/routes/notifications.py`)."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.db.models.notification_log import NotificationDeliveryChannel
from app.db.models.notification_rule import NotificationEventType
from app.services.condition_fields import CONDITION_FIELDS, operators_for
from app.services.push_channels import CHANNEL_NAMES, RECIPIENT_CHANNELS, URL_CHANNELS


class NotificationConditionCreate(BaseModel):
    """One AND-clause of a condition-based rule — see
    `app.db.models.notification_condition`'s module docstring. Validated
    against the field registry (`app.services.condition_fields`) both from
    the rule form's repeated field/operator/value rows and from a parsed
    YAML rule (`app/web/routes/notifications.py`'s import), so the two
    input paths can never disagree about what's valid."""

    field: str
    operator: str
    value: str = Field(min_length=1, max_length=255)
    mount_point: str | None = Field(default=None, max_length=255)
    sustained_seconds: int | None = Field(default=None, ge=0, le=86400)

    @field_validator("field")
    @classmethod
    def _validate_field(cls, value: str) -> str:
        if value not in CONDITION_FIELDS:
            raise ValueError(f'Unknown condition field "{value}".')
        return value

    def model_post_init(self, __context: object) -> None:
        field = CONDITION_FIELDS.get(self.field)
        if field is not None and self.operator not in operators_for(field.value_type):
            raise ValueError(
                f'Operator "{self.operator}" isn\'t valid for field "{self.field}".'
            )
        if field is not None and field.needs_mount and not self.mount_point:
            raise ValueError(f'Field "{self.field}" needs a filesystem mount point.')


class NotificationRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    enabled: bool = True
    event_types: list[str] = Field(default_factory=list)
    delivery_channel: str = NotificationDeliveryChannel.EMAIL.value
    webhook_url: str | None = Field(default=None, max_length=2048)
    # Write-only: a new token, or None/"" to keep the one already stored.
    channel_token: str | None = Field(default=None, max_length=512)
    channel_recipient: str | None = Field(default=None, max_length=255)

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

    @field_validator("delivery_channel")
    @classmethod
    def _validate_delivery_channel(cls, value: str) -> str:
        try:
            return NotificationDeliveryChannel(value).value
        except ValueError:
            raise ValueError(f'Unknown delivery channel "{value}".') from None

    def model_post_init(self, __context: object) -> None:
        channel = self.delivery_channel
        if channel in URL_CHANNELS:
            if not self.webhook_url:
                if channel == NotificationDeliveryChannel.WEBHOOK.value:
                    raise ValueError("A webhook URL is required when delivering via webhook.")
                raise ValueError(f"{CHANNEL_NAMES[channel]} needs a URL.")
            if not self.webhook_url.startswith(("http://", "https://")):
                raise ValueError("The URL must start with http:// or https://.")
        if channel in RECIPIENT_CHANNELS and not (self.channel_recipient or "").strip():
            raise ValueError(
                f"{CHANNEL_NAMES[channel]} needs a recipient "
                "(a Telegram chat id, a Pushover user key)."
            )


class NotificationTemplateUpdate(BaseModel):
    subject: str = Field(min_length=1, max_length=500)
    body: str = Field(min_length=1, max_length=4000)


class NotificationCustomTemplateCreate(BaseModel):
    """A named, reusable template (see `NotificationCustomTemplate`) — same
    fields as `NotificationTemplateUpdate` plus the name that makes it
    selectable from a rule."""

    name: str = Field(min_length=1, max_length=255)
    subject: str = Field(min_length=1, max_length=500)
    body: str = Field(min_length=1, max_length=4000)
