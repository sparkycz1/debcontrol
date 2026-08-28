"""A user-defined, cron-scheduled action against a machine, a group, or
"All machines" — see `app.scheduling` for the action registry and the
background jobs that evaluate and run these.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Enum, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup


class ScheduleTargetType(enum.StrEnum):
    MACHINE = "machine"
    GROUP = "group"
    ALL_MACHINES = "all_machines"


class ScheduledTask(Base):
    """One recurring action: run `action` (a key into the schedulable-action
    registry, `app.scheduling.actions`) against `target_type`'s machines,
    on the schedule described by `cron_expression` (standard 5-field cron,
    interpreted in UTC).

    Adding a brand new kind of action to the app doesn't require any change
    here — it only needs a `ScheduledActionSpec` registered in
    `app.scheduling.builtin_actions`, and it becomes selectable in the
    "New scheduled task" form automatically.
    """

    __tablename__ = "scheduled_tasks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Key into app.scheduling.actions' registry (e.g. "system_update",
    # "check_updates", "reboot", "shutdown") — deliberately a plain string,
    # not a native enum, so a new action can be registered without a migration.
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    # Per-action options, e.g. {"strategy": "dist_upgrade"} for system_update.
    # Shape is defined by that action's `ScheduledActionParam`s, not enforced
    # by the DB.
    action_params: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    target_type: Mapped[ScheduleTargetType] = mapped_column(
        Enum(ScheduleTargetType, name="schedule_target_type", native_enum=True), nullable=False
    )
    # Exactly one of these is set, matching target_type — enforced in the
    # route/schema layer, not via a DB constraint (SQLite in tests doesn't
    # make a CHECK constraint across nullable FKs pleasant, and there's only
    # ever one writer: the scheduling form).
    target_machine_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=True
    )
    target_machine: Mapped[Machine | None] = relationship()
    target_group_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("machine_groups.id", ondelete="CASCADE"), nullable=True
    )
    target_group: Mapped[MachineGroup | None] = relationship()

    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Denormalized so the per-minute tick (`app.scheduling.jobs.run_due_scheduled_tasks`)
    # is a single indexed `WHERE next_run_at <= now` query instead of every
    # tick re-parsing every enabled task's cron expression. Recomputed on
    # create/edit and after every run.
    next_run_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # Short human-readable outcome of the most recent run (e.g. "Triggered
    # for 3 machine(s), 1 skipped."), not a full log — there's no per-run
    # row for scheduled triggers, same reasoning as power actions: the
    # underlying job (update run / power command) already records what
    # matters, this is just "did the schedule itself fire".
    last_run_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"ScheduledTask(id={self.id!r}, name={self.name!r}, "
            f"action={self.action!r}, cron={self.cron_expression!r})"
        )
