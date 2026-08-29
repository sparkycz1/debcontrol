"""One daily, fleet-wide snapshot of the counts the Dashboard already shows
live — see `app.services.fleet_stats` for the shared queries (used both here
and by the live Dashboard, so the two never drift apart) and
`app.tasks.jobs.record_fleet_snapshot` for the daily job that writes one row
here.

Kept as a handful of plain integer columns per day, not a generic time-series
table, since the set of counts worth trending is small, fixed, and already
defined by the Dashboard — there's no ad-hoc metric a user can add here.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Date, Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class FleetSnapshot(Base):
    __tablename__ = "fleet_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # One row per calendar day (UTC) — the daily job is a no-op if today's
    # row already exists (e.g. a worker restart re-firing the cron tick),
    # enforced here too via a unique constraint, not just in the job.
    snapshot_date: Mapped[date] = mapped_column(Date, unique=True, nullable=False, index=True)

    total_machines: Mapped[int] = mapped_column(Integer, nullable=False)
    online_machines: Mapped[int] = mapped_column(Integer, nullable=False)
    offline_machines: Mapped[int] = mapped_column(Integer, nullable=False)
    # Same definition as the Dashboard's "Needs updates" card: at least one
    # of apt/flatpak/snap has an upgradable package.
    needs_updates: Mapped[int] = mapped_column(Integer, nullable=False)
    needs_security_updates: Mapped[int] = mapped_column(Integer, nullable=False)
    needs_reboot: Mapped[int] = mapped_column(Integer, nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"FleetSnapshot(snapshot_date={self.snapshot_date!r}, total={self.total_machines!r})"
