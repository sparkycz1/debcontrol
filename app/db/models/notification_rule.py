"""Notification rules — "when X happens, tell these people, about these
machines" — and the (small, fixed, code-defined) set of events that can
trigger one. See `app.services.notifications` for the dispatch/send logic
that actually reads these; this module only holds the data.

**Recipients** are the union of a rule's directly-listed `users` and every
member of its `user_groups` (`app.db.models.user_group.UserGroup`) — a
user with no `User.email` set is silently skipped, not an error, the same
"missing config = no-op" spirit `AppSettings.smtp_enabled` already has.

**Scope** narrows *which machines* a rule cares about: empty `machines`
and `machine_groups` means "every machine" (matching `MachineGroup`'s own
"All machines" convention — see `app/web/routes/machine_groups.py`);
either list, if non-empty, is added to the match set. An event with no
machine at all (none currently exist, but the model doesn't assume one
always will) matches every scope, since there's nothing to check it
against.

**Delivery** is email only, for now, through the SMTP relay configured in
Settings → Integrations (`AppSettings.smtp_*`) — see
`app.services.notifications.send_notification_email`. A rule with no
matching recipients, or an SMTP relay that isn't enabled, is a silent
no-op rather than an error: notification delivery must never be able to
break whatever background job the triggering event happened during.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, Column, ForeignKey, String, Table, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.machine import Machine
    from app.db.models.machine_group import MachineGroup
    from app.db.models.user import User
    from app.db.models.user_group import UserGroup


class NotificationEventType(enum.StrEnum):
    """The fixed set of events a rule can fire on. Adding a new one means
    adding a member here, wiring exactly one `notify(...)` call at the
    point the event actually happens (see `app.services.notifications`'s
    module docstring for the current call sites), and adding its default
    subject/body in `_DEFAULT_TEMPLATES` (`app.services.notifications`) —
    the same three-step recipe every existing member below followed."""

    MACHINE_UNREACHABLE = "machine.unreachable"
    MACHINE_REACHABLE_AGAIN = "machine.reachable_again"
    UPDATE_RUN_FAILED = "machine.update_run.failed"
    # Fired when the AI assistant's scheduled fleet summary
    # (Settings → AI Assistant — frequency/provider/model still configured
    # there, since that's about *which model writes it*, not *who hears
    # about it*) finishes generating a new report. Not machine-scoped — see
    # `app.tasks.ai_jobs._generate_fleet_summary`'s `notify(...)` call.
    FLEET_SUMMARY_GENERATED = "fleet_summary.generated"


notification_rule_users = Table(
    "notification_rule_users",
    Base.metadata,
    Column("rule_id", ForeignKey("notification_rules.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)

notification_rule_user_groups = Table(
    "notification_rule_user_groups",
    Base.metadata,
    Column("rule_id", ForeignKey("notification_rules.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "user_group_id", ForeignKey("user_groups.id", ondelete="CASCADE"), primary_key=True
    ),
)

notification_rule_machines = Table(
    "notification_rule_machines",
    Base.metadata,
    Column("rule_id", ForeignKey("notification_rules.id", ondelete="CASCADE"), primary_key=True),
    Column("machine_id", ForeignKey("machines.id", ondelete="CASCADE"), primary_key=True),
)

notification_rule_machine_groups = Table(
    "notification_rule_machine_groups",
    Base.metadata,
    Column("rule_id", ForeignKey("notification_rules.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "machine_group_id",
        ForeignKey("machine_groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class NotificationRule(Base):
    __tablename__ = "notification_rules"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # A JSON array of `NotificationEventType` values — same "small
    # code-defined set, stored as JSON rather than a join table" choice as
    # `Machine.readiness_missing`. Validated against the enum wherever a
    # rule is created/edited (`app/web/routes/notifications.py`), never
    # trusted as-is from the database.
    event_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    users: Mapped[list[User]] = relationship(
        secondary=notification_rule_users, lazy="selectin"
    )
    user_groups: Mapped[list[UserGroup]] = relationship(
        secondary=notification_rule_user_groups, lazy="selectin"
    )
    machines: Mapped[list[Machine]] = relationship(
        secondary=notification_rule_machines, lazy="selectin"
    )
    machine_groups: Mapped[list[MachineGroup]] = relationship(
        secondary=notification_rule_machine_groups, lazy="selectin"
    )

    @property
    def event_type_enums(self) -> list[NotificationEventType]:
        """`event_types`, parsed — silently drops any value that isn't a
        known member instead of raising, so a future removal of an event
        type doesn't turn every *other* rule's page into a 500."""
        result = []
        for raw in self.event_types:
            try:
                result.append(NotificationEventType(raw))
            except ValueError:
                continue
        return result

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"NotificationRule(id={self.id!r}, name={self.name!r})"


class NotificationTemplate(Base):
    """An admin-editable override of the built-in subject/body for one
    `NotificationEventType`. An event type with no row here just uses the
    built-in default (`app.services.notifications._DEFAULT_TEMPLATES`) —
    there's no migration/seed step needed to "install" the defaults, and
    deleting a customized template row is exactly "reset to default."""

    __tablename__ = "notification_templates"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_type: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    # Plain text, not HTML — rendered with a small `{placeholder}`
    # substitution (`app.services.notifications.render_template`), not a
    # template engine, so an admin-edited body can never execute code or
    # reach outside its own string. See that function's docstring for the
    # available placeholders.
    body: Mapped[str] = mapped_column(String(4000), nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"NotificationTemplate(event_type={self.event_type!r})"
