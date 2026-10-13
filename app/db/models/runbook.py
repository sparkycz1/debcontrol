"""Runbooks: a saved sequence of commands, with parameters, that can be
run on machines (`app.services.runbooks`).

A runbook is written by someone who could type the same commands into the
terminal (`action.terminal`); running one is its own, narrower permission
(`runbook.run`) — the point is that an operator can restart the stack or
rotate a log the documented way without holding a shell.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.machine import Machine
from app.db.pg_enum import pg_enum


class RunbookRunStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class Runbook(Base):
    __tablename__ = "runbooks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # [{"name": ..., "command": ...}] in order; a command may use
    # `{{key}}` for a parameter. A step that exits non-zero stops the run.
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    # [{"key": ..., "label": ..., "default": ...}]
    params: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"Runbook(id={self.id!r}, name={self.name!r})"


class RunbookRun(Base):
    """One runbook on one machine. Runs started together share a
    `batch_id`. The commands actually run are kept on the run itself, so
    its record stays true after the runbook is edited or deleted."""

    __tablename__ = "runbook_runs"
    __table_args__ = (Index("ix_runbook_runs_batch_id", "batch_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    runbook_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("runbooks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    runbook_name: Mapped[str] = mapped_column(String(120), nullable=False)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True
    )
    machine: Mapped[Machine] = relationship()
    batch_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    status: Mapped[RunbookRunStatus] = mapped_column(
        pg_enum(RunbookRunStatus, name="runbook_run_status"),
        nullable=False,
        default=RunbookRunStatus.PENDING,
    )
    # [{"name": ..., "command": ...}] with the parameters already filled in.
    commands: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    started_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"RunbookRun(id={self.id!r}, status={self.status!r})"
