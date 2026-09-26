"""A dated, attributed note on a machine — "replaced the PSU", "moved to
rack B4", "don't reboot before Friday" — shown on the machine's History
tab alongside what debcontrol itself recorded. The free-form, undated
runbook (`Machine.runbook`) stays the place for standing instructions;
a note is an entry in the machine's history.

Adding or deleting one needs `machine.manage` (the same permission that
edits the runbook) and is audit-logged.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

MAX_NOTE_LENGTH = 4000


class MachineNote(Base):
    __tablename__ = "machine_notes"
    __table_args__ = (Index("ix_machine_notes_machine_id_created_at", "machine_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    # The author's username at the time — kept as text (like the audit
    # log's `actor`) so a note outlives its author's account.
    author: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
