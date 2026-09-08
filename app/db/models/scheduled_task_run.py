"""One firing of a `ScheduledTask` — see `app.scheduling.jobs._run_scheduled_task`
for where these get written.

`ScheduledTask.last_run_at`/`last_run_summary` (the two columns the task
list itself shows) only ever remember the *most recent* firing; this table
is the full history behind them, the same relationship
`MachineUpdateRun` has to a machine's own update-run summary.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.scheduled_task import ScheduledTask
from app.db.pg_enum import pg_enum


class ScheduledTaskRunStatus(enum.StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ScheduledTaskRun(Base):
    """A single automatic (or "Run now") firing of a scheduled task —
    tied to the task's own lifecycle (`ondelete="CASCADE"`), the same way
    `MachineUpdateRun` is tied to its machine: deleting the schedule
    deletes its history with it, rather than leaving orphaned rows nothing
    can reach any more."""

    __tablename__ = "scheduled_task_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    scheduled_task_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scheduled_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scheduled_task: Mapped[ScheduledTask] = relationship()

    # The action key at the moment this run fired — kept even though
    # `ScheduledTask.action` can be edited afterwards, so a run's own row
    # always says what it actually did, not what the task happens to do now.
    action: Mapped[str] = mapped_column(String(100), nullable=False)

    status: Mapped[ScheduledTaskRunStatus] = mapped_column(
        pg_enum(ScheduledTaskRunStatus, name="scheduled_task_run_status"), nullable=False
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)

    # How many machines the underlying action was attempted/skipped for —
    # the same two numbers `ScheduledTask.last_run_summary` already
    # summarizes in prose, kept structured here for the history table's
    # own columns.
    attempted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    started_at: Mapped[datetime] = mapped_column(nullable=False)
    finished_at: Mapped[datetime] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"ScheduledTaskRun(id={self.id!r}, scheduled_task_id={self.scheduled_task_id!r}, "
            f"status={self.status!r})"
        )
