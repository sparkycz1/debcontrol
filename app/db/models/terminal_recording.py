"""What one browser terminal session showed — kept only when an
administrator turned recording on (`AppSettings.terminal_recording_enabled`,
off by default), and replayed from Audit → Terminal recordings by an
account with `audit.view`.

Only the terminal's *output* is stored, never the keystrokes: a password
typed at a prompt is not echoed, so it is not in the recording, while
everything the session printed is — including a secret someone `cat`s.
That is why the recording is stored encrypted (`data_encrypted`, the same
key as every other stored secret, and so re-encrypted by a full backup's
restore like the rest), kept for a limited time
(`AppSettings.terminal_recording_retention_days`) and why watching one is
itself written to the audit log.

`machine_id` is `SET NULL`: a recording is evidence of what was done, so
it outlives the machine it was done on (`machine_name` keeps the name).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, LargeBinary, String, false
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TerminalRecording(Base):
    __tablename__ = "terminal_recordings"
    __table_args__ = (
        Index("ix_terminal_recordings_started_at", "started_at"),
        Index("ix_terminal_recordings_machine_id_started_at", "machine_id", "started_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("machines.id", ondelete="SET NULL"), nullable=True
    )
    machine_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # The account's username at the time, kept as text like the audit log's
    # `actor`, so a recording outlives the account.
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(nullable=False)
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False)
    cols: Mapped[int] = mapped_column(Integer, nullable=False)
    rows: Mapped[int] = mapped_column(Integer, nullable=False)
    # Bytes of terminal output recorded, before compression.
    output_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    # The session printed more than one recording may hold; the rest of it
    # was not recorded (`app.services.terminal_recording.MAX_OUTPUT_BYTES`).
    truncated: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), nullable=False
    )
    # The asciicast, compressed and encrypted — see
    # `app.services.terminal_recording.pack`.
    data_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
