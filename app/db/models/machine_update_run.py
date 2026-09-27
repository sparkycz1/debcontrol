"""One run of the apt update/upgrade/autoremove/autoclean sequence on a
machine — see `app.ssh.updates` for the actual commands and `app.tasks.jobs`
for the background job that executes and records it.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, false, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.machine import Machine
from app.db.pg_enum import pg_enum


class UpgradeStrategy(enum.StrEnum):
    """How an update run upgrades apt packages (`app.ssh.updates`):

    - `upgrade` — `apt-get upgrade`: never removes a package or installs a
      new one; an upgrade that would need either is held back.
    - `full_upgrade` — `apt-get full-upgrade`: may install new dependencies
      and remove conflicting packages (what Proxmox VE recommends).
    - `dist_upgrade` — `apt-get dist-upgrade`, the older name of exactly the
      same thing as `full-upgrade`; kept so existing scheduled tasks, API
      calls and stored runs keep working, no longer offered in the forms.
    - `security` — only packages with a pending update from a `*-security`
      suite, via `apt-get install --only-upgrade`.
    """

    DIST_UPGRADE = "dist_upgrade"
    FULL_UPGRADE = "full_upgrade"
    UPGRADE = "upgrade"
    SECURITY = "security"



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

    # Reboot the machine afterwards — only when the update left it needing
    # one (app.tasks.jobs._finish_update_run).
    reboot_if_required: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), nullable=False
    )
    # "not_needed" / "rebooted" (and back within the wait) / "not_back"
    # (rebooted, but never answered again) / "failed" (the reboot command
    # itself failed). None = no reboot was asked for.
    reboot_outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # A rolling batch runs one machine at a time in this order — the next
    # run starts only once this one succeeded and, if it rebooted, came
    # back. None = runs in parallel with the rest of its batch.
    rollout_position: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # A JSON object of {package_name: installed_version}, captured via
    # `dpkg-query` right before the upgrade step of a real (non-rollback)
    # run — the basis for "Roll back this update" (see
    # `app.ssh.updates.capture_package_snapshot` /
    # `app.tasks.jobs._rollback_machine_update`). NULL for a run whose
    # snapshot capture itself failed (logged, never fatal to the update
    # itself) or one predating this feature — "Roll back" simply isn't
    # offered for those. Never populated on a rollback run itself, since a
    # rollback isn't something you roll back further (see
    # `rollback_of_run_id` below).
    package_snapshot: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Set only on a rollback run, pointing at the original update run whose
    # `package_snapshot` it was rolled back to. `ON DELETE SET NULL` rather
    # than CASCADE: the retention purge (`app.tasks.jobs.
    # purge_old_machine_update_runs`) or a machine deletion may remove the
    # source run first — the rollback run's own history (what it did, to
    # which machine) stays meaningful without it, it just loses the
    # "rollback of run X" cross-reference.
    rollback_of_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("machine_update_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )

    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"MachineUpdateRun(id={self.id!r}, machine_id={self.machine_id!r}, "
            f"status={self.status!r})"
        )
