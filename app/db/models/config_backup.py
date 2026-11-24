"""One **configuration backup** of a machine: `/etc` (with `/etc/pve` on
Proxmox VE), the crontabs and the list of installed packages, copied over
SSH as one tar archive and stored as a restic snapshot in the fleet-wide
repository — see `app.services.config_backup` for how and
`app.tasks.config_backup` for the task.

The repository itself (address, password, retention) lives in
`AppSettings.config_backup_*`; a run only remembers what it produced.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Index, Integer, String, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.machine import Machine

# Run statuses. "pending" waits for a worker, "running" is under way; the
# rest are final. "partial" = stored, but some files could not be read
# (no root on the machine): the archive lists what was skipped.
PENDING = "pending"
RUNNING = "running"
SUCCEEDED = "succeeded"
PARTIAL = "partial"
FAILED = "failed"
OPEN_STATUSES = (PENDING, RUNNING)
FINAL_STATUSES = (SUCCEEDED, PARTIAL, FAILED)
STORED_STATUSES = (SUCCEEDED, PARTIAL)


class ConfigBackupRun(Base):
    __tablename__ = "config_backup_runs"
    __table_args__ = (
        Index("ix_config_backup_runs_machine_created", "machine_id", "created_at"),
        Index(
            "ix_config_backup_runs_open",
            "status",
            postgresql_where=text("status IN ('pending', 'running')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    machine: Mapped[Machine] = relationship(foreign_keys=[machine_id])

    status: Mapped[str] = mapped_column(String(16), nullable=False, default=PENDING)
    # restic's id of the snapshot written (full 64-hex id).
    snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The archive: its size, how many files and how many could not be read.
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    file_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    unreadable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # How much new data the snapshot added to the repository (deduplicated).
    added_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # A user name, or "schedule:<task name>".
    started_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
