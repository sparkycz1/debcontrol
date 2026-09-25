"""Maintenance windows — see `app.db.models.maintenance_window` for what a
window is. This module answers "is this machine in maintenance right now"
for `app.services.notifications.notify` (and the machine page's badge),
and saves a window from its validated schema for both the web form and
the REST API.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.maintenance_window import MaintenanceWindow
from app.schemas.maintenance_window import MaintenanceWindowSave

WindowState = Literal["active", "upcoming", "ended"]


def _utc(value: datetime) -> datetime:
    """Normalize a stored timestamp — SQLite (tests) hands back naive UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def window_state(window: MaintenanceWindow, now: datetime | None = None) -> WindowState:
    now = now or datetime.now(UTC)
    if _utc(window.ends_at) <= now:
        return "ended"
    if _utc(window.starts_at) > now:
        return "upcoming"
    return "active"


def covers(window: MaintenanceWindow, machine: Machine) -> bool:
    if window.all_machines:
        return True
    if any(m.id == machine.id for m in window.machines):
        return True
    return machine.group_id is not None and any(
        g.id == machine.group_id for g in window.machine_groups
    )


async def active_windows(db: AsyncSession, now: datetime | None = None) -> list[MaintenanceWindow]:
    """Every window in effect at `now` — few rows even on a large fleet (the
    `ends_at` index skips all past windows)."""
    now = now or datetime.now(UTC)
    result = await db.execute(
        select(MaintenanceWindow).where(
            MaintenanceWindow.ends_at > now, MaintenanceWindow.starts_at <= now
        )
    )
    return list(result.scalars().all())


async def active_window_for(
    db: AsyncSession, machine: Machine, now: datetime | None = None
) -> MaintenanceWindow | None:
    """The (first) window currently muting notifications about `machine`."""
    for window in await active_windows(db, now):
        if covers(window, machine):
            return window
    return None


async def apply_window_data(
    db: AsyncSession, window: MaintenanceWindow, data: MaintenanceWindowSave
) -> None:
    """Copy validated `data` onto `window` (new or existing); the caller
    adds/commits. Group/machine ids that no longer exist are dropped, same
    as a notification rule's scope pickers."""
    window.name = data.name
    window.reason = data.reason
    window.starts_at = data.starts_at
    window.ends_at = data.ends_at
    window.all_machines = data.all_machines
    groups: list[MachineGroup] = []
    machines: list[Machine] = []
    if not data.all_machines:
        if data.machine_group_ids:
            groups = list(
                (
                    await db.execute(
                        select(MachineGroup).where(MachineGroup.id.in_(data.machine_group_ids))
                    )
                )
                .scalars()
                .all()
            )
        if data.machine_ids:
            machines = list(
                (await db.execute(select(Machine).where(Machine.id.in_(data.machine_ids))))
                .scalars()
                .all()
            )
    window.machine_groups = groups
    window.machines = machines
