"""One problem of one machine's health that someone put off for a while
("Snooze for 24 hours / 7 days / until it is gone") — see
`app.services.machine_health`.

A snoozed problem stays listed, apart, and no longer counts towards the
machine's health or sends the health notification. It ends when its time
passes, when someone clears it, when the problem goes away (a later
evaluation no longer finds it), or when the problem gets worse than it was
when it was snoozed (a warning that turns critical is shown again).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MachineHealthSnooze(Base):
    __tablename__ = "machine_health_snoozes"
    __table_args__ = (UniqueConstraint("machine_id", "finding_key"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # `Finding.key` (e.g. "storage.fs:/var").
    finding_key: Mapped[str] = mapped_column(String(255), nullable=False)
    # The severity the problem had when it was snoozed.
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    # NULL = until the problem is gone.
    until: Mapped[datetime | None] = mapped_column(nullable=True)
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
