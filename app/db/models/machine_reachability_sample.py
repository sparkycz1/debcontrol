"""One TCP-reachability check result for a managed machine, historized —
the "Availability" category on the Monitoring tab.

A row is written every time `app.tasks.jobs._ping_all_machines`' per-minute
sweep actually checks a given machine (same cadence as the existing
`Machine.is_reachable`/`last_ping_at` update this sweep already does — see
`app.ssh.reachability`'s module docstring for why that's a plain TCP
connect, not ICMP ping: a host that blocks ICMP but serves SSH should
still read as reachable, and this table inherits that same reasoning).
No new SSH connection and no new probe is added anywhere — this just
*keeps* the result of the check that was already happening, instead of
only ever overwriting the same two columns on `Machine` with the latest
value.

Unlike `MachineMonitoringSample`, a row here is written whether the
machine was reachable or not — the whole point of an uptime/latency
history is that it must capture an outage, and a monitoring sample is
never even attempted when the machine's SSH port doesn't answer (SSH
auth would fail before there's anything to sample).

Purged by `app.tasks.jobs.purge_old_monitoring_samples`, alongside
`MachineMonitoringSample`, using the same
`AppSettings.monitoring_history_retention_days` (and its per-machine
override) — one retention setting for "how long does this fleet's own
history stick around", not a second knob to configure.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Float, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class MachineReachabilitySample(Base):
    __tablename__ = "machine_reachability_samples"
    __table_args__ = (
        # Same query shape as MachineMonitoringSample's own index — "this
        # machine's samples in this time range, in order" — and what the
        # retention purge deletes by.
        Index(
            "ix_machine_reachability_samples_machine_id_checked_at",
            "machine_id",
            "checked_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True
    )
    machine: Mapped[Machine] = relationship(viewonly=True)

    checked_at: Mapped[datetime] = mapped_column(nullable=False)
    reachable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # How long the TCP connect attempt took, in milliseconds — None for a
    # failed attempt (there's no meaningful "connect time" for a timeout
    # or refused connection, only for one that actually succeeded).
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)


# Imported last, and only for type checking: every class above is already
# defined by the time this module points back at the models it relates
# to, so no import cycle can leave a class half-defined (CodeQL's
# "Module-level cyclic import"). SQLAlchemy resolves the relationship
# targets by name through its registry, never through these imports.
if TYPE_CHECKING:
    from app.db.models.machine import Machine
