"""One machine's part of a **tune-up** ("Komplet"): every maintenance step
debcontrol can run, one after another, recorded step by step — see
`app.services.tune_up` for which steps there are and `app.tasks.tune_up`
for the task that runs them.

A tune-up of several machines is one `batch_id` with a run per machine.
`steps` is the plan and its outcome, a list of
`{"key", "status", "detail", "ref", "started_at", "finished_at"}` in the
order they run. `detail` is `{"code": ..., <numbers>}` or
`{"error": ...}`; `ref` holds what a step started (an update run, a
security audit, Docker jobs), so a task that stopped half way can pick the
step up again rather than start it twice.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.machine import Machine

# Run statuses. "pending" waits for its turn, "running" is under way;
# the rest are final.
PENDING = "pending"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCELLED = "cancelled"
OPEN_STATUSES = (PENDING, RUNNING)
FINAL_STATUSES = (SUCCEEDED, FAILED, CANCELLED)


class TuneUpRun(Base):
    __tablename__ = "tune_up_runs"
    __table_args__ = (
        Index("ix_tune_up_runs_batch_id", "batch_id"),
        Index(
            "ix_tune_up_runs_open",
            "status",
            postgresql_where=text("status IN ('pending', 'running')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
    batch_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True
    )
    machine: Mapped[Machine] = relationship(foreign_keys=[machine_id])

    status: Mapped[str] = mapped_column(String(16), nullable=False, default=PENDING)
    # The options the tune-up was started with (`tune_up.Options.as_dict`).
    options: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    error: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Waits for the rest of its batch: debcontrol's own host and the
    # hypervisor under it go last (`app.services.self_host`).
    hold_order: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cancel_requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    queued_at: Mapped[datetime | None] = mapped_column(nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
