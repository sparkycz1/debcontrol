"""REST API for the Dashboard's fleet-trend snapshots (Task 4) — the raw
daily series behind the Dashboard's SVG chart(s), for anyone who wants to
graph it externally (Grafana, a spreadsheet, ...). Read-only.

Gated by `machine.view`, the same permission that already governs seeing
these numbers live on the Dashboard (`app/web/routes/dashboard.py`) and in
`GET /api/v1/machines` — there's no dedicated "dashboard" permission, and
inventing one here would just be a second way to grant the same access.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_api_permission
from app.db.models.fleet_snapshot import FleetSnapshot
from app.db.models.role import Permission
from app.db.session import get_db

router = APIRouter(prefix="/api/v1/dashboard")

_view = Depends(require_api_permission(Permission.MACHINE_VIEW))


def _snapshot_to_dict(snapshot: FleetSnapshot) -> dict[str, object]:
    return {
        "date": snapshot.snapshot_date.isoformat(),
        "total_machines": snapshot.total_machines,
        "online_machines": snapshot.online_machines,
        "offline_machines": snapshot.offline_machines,
        "needs_updates": snapshot.needs_updates,
        "needs_security_updates": snapshot.needs_security_updates,
        "needs_reboot": snapshot.needs_reboot,
    }


@router.get("/trends", dependencies=[_view])
async def dashboard_trends_api(db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    """Every retained daily snapshot, oldest first — whatever the retention
    purge (`app.tasks.jobs.purge_old_fleet_snapshots`) has left in the
    table, with no further filtering here (mirrors the web Dashboard, which
    shows the same unfiltered set once there are at least two)."""
    result = await db.execute(select(FleetSnapshot).order_by(FleetSnapshot.snapshot_date.asc()))
    snapshots = list(result.scalars().all())
    return {"snapshots": [_snapshot_to_dict(s) for s in snapshots]}
