"""One systemd service unit on a managed machine, as of the last service
snapshot — see `app.ssh.services` for how it's gathered and
`app.tasks.jobs.refresh_machine_services` for how it's kept in sync.

Same shape and lifecycle as `app.db.models.machine_package.MachinePackage`:
each refresh replaces a machine's whole set of rows in one transaction
(delete-then-bulk-insert), a snapshot of "what's running right now," not a
history — and on the same cadence (`FACTS_REFRESH_INTERVAL_SECONDS`), not
the much shorter Monitoring sample interval, since a full unit listing
doesn't need to be nearly as fresh as a CPU/RAM sample does. The Monitoring
tab's own frequent "N services failed" count is a plain live count taken
at sample time (`MachineMonitoringSample.failed_services_count`), not
derived from this table.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.machine import Machine


class MachineService(Base):
    __tablename__ = "machine_services"
    __table_args__ = (
        Index("ix_machine_services_machine_id_active_state", "machine_id", "active_state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True
    )
    machine: Mapped[Machine] = relationship(viewonly=True)

    # `systemctl list-units --type=service --all`'s own columns — kept as
    # the terms systemd itself uses (not renamed/simplified) since that's
    # what an operator searching this list already knows to look for.
    unit: Mapped[str] = mapped_column(String(255), nullable=False)
    load_state: Mapped[str] = mapped_column(String(32), nullable=False)
    active_state: Mapped[str] = mapped_column(String(32), nullable=False)
    sub_state: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"MachineService(machine_id={self.machine_id!r}, unit={self.unit!r})"
