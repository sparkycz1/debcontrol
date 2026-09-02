"""One CPU/RAM/disk-usage sample for a managed machine, taken on the
Monitoring tab's own cadence (`MONITORING_INTERVAL_SECONDS`, see
`app.ssh.monitoring` and `app.tasks.jobs._sample_machine_monitoring`).

Unlike `MachinePackage`/`MachineService`, this genuinely is a history, not
a replaced snapshot — the whole point is trend graphs over a time range.
Purged by `app.tasks.jobs.purge_old_monitoring_samples` per
`AppSettings.monitoring_history_retention_days` (overridable per machine —
see `Machine.monitoring_history_retention_days`).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, BigInteger, Float, ForeignKey, Index, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.machine import Machine


class MachineMonitoringSample(Base):
    __tablename__ = "machine_monitoring_samples"
    __table_args__ = (
        # The one query this table exists to serve: "this machine's samples
        # in this time range, in order" — and the same shape the retention
        # purge deletes by.
        Index("ix_machine_monitoring_samples_machine_id_sampled_at", "machine_id", "sampled_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True
    )
    machine: Mapped[Machine] = relationship(viewonly=True)

    sampled_at: Mapped[datetime] = mapped_column(nullable=False)

    # 0-100, None if it couldn't be computed (e.g. /proc/stat unreadable).
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    ram_used_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Stored per-sample (not just read off `Machine.ram_bytes`) so a sample
    # row stays meaningful on its own even if RAM changes (or hasn't been
    # gathered by a facts refresh yet at all).
    ram_total_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Each a lightweight {"mount": ..., "use_percent": ...} dict — deliberately
    # not the fuller {mount, size_bytes, used_bytes, avail_bytes} shape
    # `Machine.filesystems`/facts use, to keep a row taken every couple of
    # minutes small. The current absolute sizes are still available from the
    # facts panel; this is for the *trend*.
    disks: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # None = couldn't tell (no `systemctl` — see app.ssh.monitoring), not
    # "zero failed services".
    failed_services_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
