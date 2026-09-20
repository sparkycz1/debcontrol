"""Condition-based notification triggers — "tell me when this machine's CPU
goes over 90%", as opposed to the fixed lifecycle events in
`app.db.models.notification_rule.NotificationEventType`. See
`app.services.condition_fields` for the curated, code-defined set of
fields a condition can reference, and
`app.tasks.jobs.evaluate_notification_conditions` for the periodic sweep
that evaluates these and calls `app.services.notifications.notify(...)`
on a match.

**Scope of "flexible"**: conditions reference a curated field registry
(CPU/RAM/load/disk-per-mount/OS-and-kernel-version/reachability/uptime/
pending-updates/reboot-required/failed-services-count — see
`app.services.condition_fields.CONDITION_FIELDS`), not an arbitrary
expression language. Within one rule, every condition must match (AND) —
for OR, create multiple rules, the same way a rule already unions its own
recipients. This keeps the field set auditable and the YAML shape
(`app/web/routes/notifications.py`'s import/export) simple enough to
hand-edit.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.machine import Machine
    from app.db.models.notification_rule import NotificationRule


class NotificationCondition(Base):
    """One AND-clause of a condition-based rule. `field` is a key into
    `app.services.condition_fields.CONDITION_FIELDS`; `value` is stored as
    text and parsed per that field's declared type when evaluated —
    kept as a plain string column (like `NotificationRule.event_types`
    stores its JSON as code-validated text) rather than a typed column,
    since the same column has to hold a number, a version string, or a
    boolean depending on which field it's paired with."""

    __tablename__ = "notification_conditions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("notification_rules.id", ondelete="CASCADE"), nullable=False
    )
    field: Mapped[str] = mapped_column(String(64), nullable=False)
    operator: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    # Only meaningful for a mount-scoped field (currently
    # "monitoring.filesystem_use_percent") — which filesystem's row to read
    # out of `Machine.filesystems`/`MachineMonitoringSample.filesystems`.
    mount_point: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # How long (seconds) the condition must hold continuously before it
    # fires — None/0 fires on the first matching sweep tick (edge-
    # triggered, like the existing unreachable/reachable-again pattern).
    sustained_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    rule: Mapped[NotificationRule] = relationship(back_populates="conditions")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"NotificationCondition(field={self.field!r}, "
            f"operator={self.operator!r}, value={self.value!r})"
        )


class NotificationConditionState(Base):
    """Per rule x machine evaluation state, persisted across sweep ticks so a
    condition notifies once on the true transition (and again after a
    false→true cycle) rather than on every tick that simply confirms
    "still matching" — the DB-backed equivalent of the in-memory
    before/after compare `app.tasks.jobs._ping_all_machines` does for
    reachability, needed here because evaluation happens on its own sweep
    rather than in the same tick that writes the underlying sample."""

    __tablename__ = "notification_condition_state"

    rule_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("notification_rules.id", ondelete="CASCADE"), primary_key=True
    )
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), primary_key=True
    )
    matched: Mapped[bool] = mapped_column(nullable=False, default=False)
    first_matched_at: Mapped[datetime | None] = mapped_column(nullable=True)
    notified_at: Mapped[datetime | None] = mapped_column(nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    rule: Mapped[NotificationRule] = relationship()
    machine: Mapped[Machine] = relationship()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"NotificationConditionState(rule_id={self.rule_id!r}, "
            f"machine_id={self.machine_id!r}, matched={self.matched!r})"
        )
