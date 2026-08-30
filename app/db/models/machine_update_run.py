"""One run of the apt update/upgrade/autoremove/autoclean sequence on a
machine — see `app.ssh.updates` for the actual commands and `app.tasks.jobs`
for the background job that executes and records it.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.machine import Machine
from app.db.pg_enum import pg_enum


class UpgradeStrategy(enum.StrEnum):
    DIST_UPGRADE = "dist_upgrade"
    FULL_UPGRADE = "full_upgrade"


class UpdateRunStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class MachineUpdateRun(Base):
    """A single update attempt, always: `apt-get update`, then the chosen
    upgrade strategy, then `autoremove` and `autoclean` unconditionally
    (see `app.ssh.updates.build_update_command`)."""

    __tablename__ = "machine_update_runs"
    __table_args__ = (Index("ix_machine_update_runs_batch_id", "batch_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True
    )
    machine: Mapped[Machine] = relationship()

    # Shared across every run triggered together from a group/"All machines"
    # action, so they can be listed as one batch. NULL for a single-machine
    # trigger. Not a foreign key to anything — it's just a grouping key.
    batch_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)

    strategy: Mapped[UpgradeStrategy] = mapped_column(
        pg_enum(UpgradeStrategy, name="upgrade_strategy"), nullable=False
    )
    status: Mapped[UpdateRunStatus] = mapped_column(
        pg_enum(UpdateRunStatus, name="update_run_status"),
        nullable=False,
        default=UpdateRunStatus.PENDING,
    )

    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"MachineUpdateRun(id={self.id!r}, machine_id={self.machine_id!r}, "
            f"status={self.status!r})"
        )
