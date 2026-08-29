"""Fleet-wide machine counts — the exact queries the Dashboard shows live
(`app.web.routes.dashboard`), factored out so the daily snapshot job
(`app.tasks.jobs.record_fleet_snapshot`) records precisely the same
definitions rather than a second, potentially-drifting copy of them.
"""

from __future__ import annotations

from typing import TypedDict

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine


class FleetStats(TypedDict):
    total: int
    online: int
    offline: int
    needs_updates: int
    needs_security_updates: int
    needs_reboot: int


async def compute_fleet_stats(db: AsyncSession) -> FleetStats:
    total = (await db.execute(select(func.count()).select_from(Machine))).scalar_one()
    online = (
        await db.execute(
            select(func.count()).select_from(Machine).where(Machine.is_reachable.is_(True))
        )
    ).scalar_one()
    offline = (
        await db.execute(
            select(func.count()).select_from(Machine).where(Machine.is_reachable.is_(False))
        )
    ).scalar_one()
    needs_updates = (
        await db.execute(
            select(func.count())
            .select_from(Machine)
            .where(
                (Machine.upgradable_count > 0)
                | (Machine.flatpak_upgradable_count > 0)
                | (Machine.snap_upgradable_count > 0)
            )
        )
    ).scalar_one()
    needs_security_updates = (
        await db.execute(
            select(func.count()).select_from(Machine).where(Machine.security_upgradable_count > 0)
        )
    ).scalar_one()
    needs_reboot = (
        await db.execute(
            select(func.count()).select_from(Machine).where(Machine.reboot_required.is_(True))
        )
    ).scalar_one()
    return {
        "total": total,
        "online": online,
        "offline": offline,
        "needs_updates": needs_updates,
        "needs_security_updates": needs_security_updates,
        "needs_reboot": needs_reboot,
    }
