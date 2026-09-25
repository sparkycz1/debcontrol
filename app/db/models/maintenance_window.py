"""A maintenance window: a time range during which notifications about
certain machines are muted — "we're patching the prod group Saturday
02:00-04:00, don't page anyone about it going offline."

Scope is either every machine (`all_machines`) or any mix of listed
machine groups and individual machines. Only machine-scoped events are
affected (unreachable/reachable again, update run failed/succeeded,
onboarding, condition matches); events not about a machine (endpoint
checks, the fleet summary) still go out. A muted delivery is not lost
silently: `app.services.notifications.notify` records it in the delivery
history as `suppressed`, naming the window. See
`app.services.maintenance_windows` for the matching logic.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Column, ForeignKey, Index, String, Table, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.machine import Machine
    from app.db.models.machine_group import MachineGroup


maintenance_window_machines = Table(
    "maintenance_window_machines",
    Base.metadata,
    Column(
        "window_id", ForeignKey("maintenance_windows.id", ondelete="CASCADE"), primary_key=True
    ),
    Column("machine_id", ForeignKey("machines.id", ondelete="CASCADE"), primary_key=True),
)

maintenance_window_machine_groups = Table(
    "maintenance_window_machine_groups",
    Base.metadata,
    Column(
        "window_id", ForeignKey("maintenance_windows.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "machine_group_id",
        ForeignKey("machine_groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class MaintenanceWindow(Base):
    __tablename__ = "maintenance_windows"
    __table_args__ = (
        # Every notification asks "which windows are active right now" —
        # i.e. not yet ended; ends_at bounds that scan as history grows.
        Index("ix_maintenance_windows_ends_at", "ends_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    starts_at: Mapped[datetime] = mapped_column(nullable=False)
    ends_at: Mapped[datetime] = mapped_column(nullable=False)
    all_machines: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Kept as text, not a user FK: the window (and its audit meaning)
    # outlives the account that scheduled it.
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    machines: Mapped[list[Machine]] = relationship(
        secondary=maintenance_window_machines, lazy="selectin", order_by="Machine.name"
    )
    machine_groups: Mapped[list[MachineGroup]] = relationship(
        secondary=maintenance_window_machine_groups,
        lazy="selectin",
        order_by="MachineGroup.name",
    )
