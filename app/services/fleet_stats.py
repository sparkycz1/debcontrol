"""Fleet-wide machine counts — the exact queries the Dashboard shows live
(`app.web.routes.dashboard`), factored out so the daily snapshot job
(`app.tasks.jobs.record_fleet_snapshot`) records precisely the same
definitions rather than a second, potentially-drifting copy of them.

`group_ids` narrows every count to machines in those groups, for the live
Dashboard of an account restricted to specific machine groups (see
`app.services.access_scope`). The snapshot job passes nothing and keeps
recording genuine fleet-wide totals — it runs with no "current user" to
scope to, and its historical series would be meaningless if it varied by
whoever happened to be logged in.
"""

from __future__ import annotations

import uuid
from collections.abc import Set as AbstractSet
from typing import TypedDict

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine


class FleetStats(TypedDict):
    total: int
    online: int
    offline: int
    needs_updates: int
    needs_security_updates: int
    needs_reboot: int


async def compute_fleet_stats(
    db: AsyncSession, group_ids: AbstractSet[uuid.UUID] | None = None
) -> FleetStats:
    """Every count in one place. `group_ids=None` (the default) means no
    scoping at all — the whole fleet."""

    async def _count(*conditions: ColumnElement[bool]) -> int:
        query = select(func.count()).select_from(Machine)
        if group_ids is not None:
            query = query.where(Machine.group_id.in_(group_ids))
        for condition in conditions:
            query = query.where(condition)
        return (await db.execute(query)).scalar_one()

    total = await _count()
    online = await _count(Machine.is_reachable.is_(True))
    offline = await _count(Machine.is_reachable.is_(False))
    needs_updates = await _count(
        (Machine.upgradable_count > 0)
        | (Machine.flatpak_upgradable_count > 0)
        | (Machine.snap_upgradable_count > 0)
    )
    needs_security_updates = await _count(Machine.security_upgradable_count > 0)
    needs_reboot = await _count(Machine.reboot_required.is_(True))
    return {
        "total": total,
        "online": online,
        "offline": offline,
        "needs_updates": needs_updates,
        "needs_security_updates": needs_security_updates,
        "needs_reboot": needs_reboot,
    }
