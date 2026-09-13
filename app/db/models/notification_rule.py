"""Notification rules — "when X happens, tell these people, about these
machines" — and the (small, fixed, code-defined) set of events that can
trigger one. See `app.services.notifications` for the dispatch/send logic
that actually reads these; this module only holds the data.

**Recipients** are the union of a rule's directly-listed `users` and every
active user whose `Role` is one of the rule's `roles` — deliberately
targeting the existing RBAC `Role` rather than a separate notification-only
grouping concept (an earlier round of this feature had its own `UserGroup`
model; it was folded into `Role` once it became clear "who should hear
about what" almost always tracks "what job does this account do", which a
role already answers, and a second, parallel grouping concept just for
notifications was one more list to keep in sync as accounts come and go).
A user with no `User.email` set is silently skipped, not an error, the same
"missing config = no-op" spirit `AppSettings.smtp_enabled` already has.

**Scope** narrows *which machines* a rule cares about: empty `machines`
and `machine_groups` means "every machine" (matching `MachineGroup`'s own
"All machines" convention — see `app/web/routes/machine_groups.py`);
either list, if non-empty, is added to the match set. An event with no
machine at all (none currently exist, but the model doesn't assume one
always will) matches every scope, since there's nothing to check it
against.

**Delivery** is email (through the SMTP relay configured in Settings →
Integrations, `AppSettings.smtp_*`) or a webhook (`webhook_url`, plain
JSON POST) — one or the other per rule, `delivery_channel` says which.
For email, a rule with no matching recipients, or an SMTP relay that
isn't enabled, is a silent no-op; a webhook rule with SMTP disabled still
fires (the two channels don't depend on each other). Either way, a
delivery attempt is never able to break whatever background job the
triggering event happened during — see `app.services.notifications.notify`
— and every attempt (success or failure) is recorded in
`app.db.models.notification_log.NotificationLog` for troubleshooting.
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
    from app.db.models.notification_condition import NotificationCondition
    from app.db.models.role import Role
    from app.db.models.user import User


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
    # The success counterpart of the above — fired from the same
    # `app.tasks.jobs._run_machine_update`/`_run_group_update` call sites,
    # on `UpdateRunStatus.SUCCEEDED` instead of `.FAILED`. Kept as its own
    # event type (not "update run finished either way") so a rule can opt
    # into just failures, just successes, or both.
    UPDATE_RUN_SUCCEEDED = "machine.update_run.succeeded"
    # Fired once, right after a machine finishes onboarding successfully
    # (`app.tasks.jobs._run_onboarding`) — "a new machine just joined the
    # fleet," as distinct from every other event here being about a machine
    # already onboarded.
    MACHINE_ONBOARDED = "machine.onboarded"
    # Fired when the AI assistant's scheduled fleet summary
    # (Settings → AI Assistant — frequency/provider/model still configured
    # there, since that's about *which model writes it*, not *who hears
    # about it*) finishes generating a new report. Not machine-scoped — see
    # `app.tasks.ai_jobs._generate_fleet_summary`'s `notify(...)` call.
    FLEET_SUMMARY_GENERATED = "fleet_summary.generated"
    # Fired by the condition-evaluation sweep (`app.tasks.jobs.
    # evaluate_notification_conditions`) whenever a rule's own
    # `NotificationCondition` row(s) — CPU/RAM/disk/facts thresholds, see
    # `app.db.models.notification_condition` and
    # `app.services.condition_fields` — all match for a machine in scope,
    # on the true transition (and again after a false→true cycle), not
    # every tick that simply confirms "still matching." A rule with
    # `conditions` set has this added to its own `event_types`
    # automatically when saved (`app/web/routes/notifications.py`) so the
    # existing `notify()`/`_matching_rules` dispatch path needs no special
    # case for condition-based rules.
    CONDITION_MATCHED = "machine.condition_matched"


notification_rule_users = Table(
    "notification_rule_users",
    Base.metadata,
    Column("rule_id", ForeignKey("notification_rules.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)

notification_rule_roles = Table(
    "notification_rule_roles",
    Base.metadata,
    Column("rule_id", ForeignKey("notification_rules.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
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
    roles: Mapped[list[Role]] = relationship(
        secondary=notification_rule_roles, lazy="selectin"
    )
    machines: Mapped[list[Machine]] = relationship(
        secondary=notification_rule_machines, lazy="selectin"
    )
    machine_groups: Mapped[list[MachineGroup]] = relationship(
        secondary=notification_rule_machine_groups, lazy="selectin"
    )
    # Condition-based triggers (CPU/RAM/disk/facts thresholds) — see
    # `app.db.models.notification_condition`. A rule with any of these is
    # evaluated by `app.tasks.jobs.evaluate_notification_conditions` in
    # addition to (not instead of) its `event_types` above.
    conditions: Mapped[list[NotificationCondition]] = relationship(
        back_populates="rule", cascade="all, delete-orphan", lazy="selectin"
    )

    # A named, reusable template this rule sends instead of the per-event
    # default/override (`NotificationTemplate` below) — see
    # `NotificationCustomTemplate`'s own docstring. `None` (the default)
    # keeps a rule's existing behavior unchanged.
    custom_template_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("notification_custom_templates.id", ondelete="SET NULL"), nullable=True
    )
    custom_template: Mapped[NotificationCustomTemplate | None] = relationship(lazy="selectin")

    # "email" (default) or "webhook" — see the module docstring's Delivery
    # section. Plain string, not a native DB enum, same "small code-defined
    # set" reasoning as `event_types` above: adding a third channel later
    # needs no migration to widen a DB-level enum type.
    delivery_channel: Mapped[str] = mapped_column(String(16), default="email", nullable=False)
    # Required (validated in app/web/routes/notifications.py) when
    # delivery_channel is "webhook"; unused/ignored for "email".
    webhook_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)

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


class NotificationCustomTemplate(Base):
    """A named, reusable subject/body an admin writes once and any number of
    `NotificationRule`s can opt into via `NotificationRule.custom_template_id`
    — distinct from `NotificationTemplate` above, which is a single
    per-event-type override applied to *every* rule that fires that event.
    A rule with no `custom_template_id` keeps using that per-event
    default/override exactly as before ("missing config = no change" — same
    spirit as everywhere else in this module); setting one overrides it for
    that rule alone, regardless of which event actually fired. Same plain-
    text `{placeholder}` substitution as `NotificationTemplate`
    (`app.services.notifications.render_template`) — every placeholder
    listed there works here too. Deleting a template in use just clears the
    referencing rule(s) back to their per-event default (`ondelete="SET
    NULL"` on the FK), never breaks them."""

    __tablename__ = "notification_custom_templates"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[str] = mapped_column(String(4000), nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"NotificationCustomTemplate(name={self.name!r})"
