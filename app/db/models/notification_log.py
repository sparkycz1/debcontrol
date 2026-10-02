"""Notification delivery history — one row per actual send *attempt*
(one per recipient for the email channel, one per rule for the webhook
channel), success or failure. Distinct from the audit log: `app.audit`
records *that* a rule matched and a notification was warranted; this
records *whether actually sending it worked* — the two can disagree (a
matched rule with a down SMTP relay logs nothing in `app.audit` beyond
the triggering event itself, but gets a `status="failed"` row here).

Written by `app.services.notifications.notify` (real sends) and
`send_test_notification` (the "Send test" button on a rule's edit page,
`app/web/routes/notifications.py` — flagged `is_test=True` so it never
gets confused with a real delivery in the history list). Purged on its
own schedule (`AppSettings.notification_log_retention_days`,
`app.tasks.jobs.purge_old_notification_logs`) the same way monitoring
samples and update-run records are — this is delivery history for
troubleshooting, not a compliance record, so it defaults to a bounded
window rather than "keep forever."
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class NotificationDeliveryChannel(enum.StrEnum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    # Push services homelabs actually use — see app.services.push_channels.
    NTFY = "ntfy"
    GOTIFY = "gotify"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    PUSHOVER = "pushover"
    # Team chat incoming webhooks.
    MATTERMOST = "mattermost"
    SLACK = "slack"
    TEAMS = "teams"


class NotificationDeliveryStatus(enum.StrEnum):
    SENT = "sent"
    FAILED = "failed"
    # Not delivered on purpose: the machine was inside an active
    # maintenance window (`target` names the window) — see
    # `app.services.maintenance_windows`.
    SUPPRESSED = "suppressed"


class NotificationLog(Base):
    __tablename__ = "notification_logs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # Nullable + a denormalized `rule_name` copy: a deleted rule's history
    # should stay readable ("what did this rule used to send") rather than
    # vanish or block the delete, so the FK is SET NULL rather than CASCADE.
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("notification_rules.id", ondelete="SET NULL"), nullable=True, index=True
    )
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    # The email address or webhook URL this particular attempt went to.
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    machine_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    is_test: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    sent_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False, index=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"NotificationLog(rule_name={self.rule_name!r}, channel={self.channel!r}, "
            f"status={self.status!r})"
        )
