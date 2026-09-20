"""One CPU/load/RAM/network/disk-I/O/filesystem-usage sample for a managed
machine, taken on the Monitoring tab's own cadence (`MONITORING_INTERVAL_SECONDS`, see
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
    # 1/5/15-minute load averages (`/proc/loadavg`) — a count of
    # runnable+uninterruptible processes, not a percentage; can exceed a
    # machine's own `cpu_cores`, unlike cpu_percent.
    load1: Mapped[float | None] = mapped_column(Float, nullable=True)
    load5: Mapped[float | None] = mapped_column(Float, nullable=True)
    load15: Mapped[float | None] = mapped_column(Float, nullable=True)
    ram_used_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Stored per-sample (not just read off `Machine.ram_bytes`) so a sample
    # row stays meaningful on its own even if RAM changes (or hasn't been
    # gathered by a facts refresh yet at all).
    ram_total_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Each {"iface": ..., "rx_bytes": ..., "tx_bytes": ...} — cumulative
    # counters since boot (loopback excluded), one entry per interface
    # found. The Monitoring tab's graphs compute a rate (bytes/sec) from
    # the delta between consecutive samples — see
    # app.services.monitoring_history.
    network_io: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # Each {"device": ..., "read_bytes": ..., "write_bytes": ...} —
    # cumulative counters since boot, one entry per whole disk found. A
    # different question from `filesystems` below (throughput vs. how
    # full a mount is), sampled here for the same reason.
    disk_io: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # Each {"mount": ..., "size_bytes": ..., "used_bytes": ..., "avail_bytes":
    # ..., "use_percent": ...} — same shape as `Machine.filesystems` (the
    # facts snapshot), but historized on this table's own shorter cadence
    # so the Monitoring tab can chart usage *over time*, not just show the
    # single most recent reading.
    filesystems: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # None = couldn't tell (no `systemctl` — see app.ssh.monitoring), not
    # "zero failed services".
    failed_services_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Hardware — only ever populated for a physical machine
    # (Machine.is_physical); empty/None on a VM (not "nothing found") —
    # see app.ssh.monitoring's own _HARDWARE_COMMAND. ---
    # Each {"name": ..., "celsius": ...}.
    sensor_temps: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # Each {"name": ..., "rpm": ...}.
    sensor_fans: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # Each {"device": ..., "healthy": bool | None}.
    smart_disks: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # Cumulative RAPL package-energy counter, microjoules — a rate (watts)
    # is computed from consecutive samples the same way network/disk I/O
    # already is, see app.services.monitoring_history.
    cpu_energy_uj: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Already a rate (watts) straight from nvidia-smi, not a counter.
    gpu_power_watts: Mapped[float | None] = mapped_column(Float, nullable=True)
