"""One detected change to a machine's configuration or state — "the
kernel went from 6.1.0-25 to 6.1.0-26", "port 8080 started listening",
"user deploy was added to sudo", "3 new security updates" — written by
`app.services.config_drift` when a facts refresh or an update check sees
something different from the previous one.

Shown on the machine's History tab (`app.services.machine_timeline`) and,
for notification rules listening to `machine.config_changed` /
`machine.security_updates`, sent out. Unattended-sweep output, so these
are *not* audit log entries (see CLAUDE.md on what the audit log is for).
Purged after `RETENTION_DAYS` by the daily purge job.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# How long detected changes are kept.
RETENTION_DAYS = 365


class MachineChange(Base):
    __tablename__ = "machine_changes"
    __table_args__ = (
        # Every read is "one machine's changes, newest first" (History tab)
        # and the purge is a time cutoff.
        Index("ix_machine_changes_machine_id_detected_at", "machine_id", "detected_at"),
        Index("ix_machine_changes_detected_at", "detected_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    detected_at: Mapped[datetime] = mapped_column(nullable=False)
    # "facts" (a configuration fact changed) or "security" (new security
    # updates became available) — decides the notification event.
    category: Mapped[str] = mapped_column(String(16), nullable=False)
    # Which fact: see `app.services.config_drift.TRACKED_FIELDS`.
    field: Mapped[str] = mapped_column(String(32), nullable=False)
    # Human-readable before/after (a set-valued fact stores what was
    # removed/added instead). Plain text, shown escaped.
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
