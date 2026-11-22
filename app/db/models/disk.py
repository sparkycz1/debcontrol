"""Physical disks, followed by their serial number rather than by the
machine they sit in — see `app.services.disk_history`.

- `Disk` — one per (model, serial) ever seen in a machine's S.M.A.R.T.
  data. A disk moved to another machine keeps its row, its history and its
  events; `machine_id` is where it was seen last.
- `DiskSample` — the disk's readings at most once an hour (temperature,
  wear, data written, error counters), or sooner when a counter changed.
  For the temperature chart and the failure trend. Kept as long as the
  monitoring history (`AppSettings.monitoring_history_retention_days`).
- `DiskEvent` — what happened to it, kept for good: first seen, moved,
  S.M.A.R.T. failed or passed again, an error counter that grew, a wear
  or temperature level crossed, ZFS errors or a ZFS state change. An
  event stays even when the problem goes away on its own.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Disk(Base):
    __tablename__ = "disks"
    __table_args__ = (UniqueConstraint("model", "serial"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    serial: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    # "nvme", "sata", "scsi", ... as smartctl reports the protocol.
    kind: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rotation_rpm: Mapped[int | None] = mapped_column(Integer, nullable=True)
    capacity_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    firmware: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Where it was seen last; SET NULL when that machine is deleted, so the
    # disk's history stays.
    machine_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("machines.id", ondelete="SET NULL"), nullable=True, index=True
    )
    machine_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    # The newest S.M.A.R.T. summary as `app.ssh.smart.parse_smart_device`
    # returns it, attributes included (for the detail page and the report).
    latest: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # `app.services.disk_history.predict` at the last reading.
    prediction: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    event_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )


class DiskSample(Base):
    __tablename__ = "disk_samples"
    __table_args__ = (Index("ix_disk_samples_disk_id_sampled_at", "disk_id", "sampled_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
    disk_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("disks.id", ondelete="CASCADE"), nullable=False
    )
    sampled_at: Mapped[datetime] = mapped_column(nullable=False, index=True)
    temperature_c: Mapped[float | None] = mapped_column(Float, nullable=True)
    power_on_hours: Mapped[int | None] = mapped_column(Integer, nullable=True)
    wear_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    written_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # `{name: count}` — see `app.ssh.smart._counters`, plus `io_errors`
    # and the ZFS read/write/checksum errors of the disk.
    counters: Mapped[dict[str, int] | None] = mapped_column(JSON, nullable=True)


class DiskEvent(Base):
    __tablename__ = "disk_events"
    __table_args__ = (Index("ix_disk_events_disk_id_occurred_at", "disk_id", "occurred_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
    disk_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("disks.id", ondelete="CASCADE"), nullable=False
    )
    machine_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("machines.id", ondelete="SET NULL"), nullable=True
    )
    machine_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(nullable=False, index=True)
    # `app.services.disk_history.EVENT_KINDS`.
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    # "warning" / "critical" / "info" — what the event says about the disk.
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    # What the event's text is built from: `{"counter", "from", "to"}`,
    # `{"from_machine", "to_machine"}`, `{"level", "value"}`, ...
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
