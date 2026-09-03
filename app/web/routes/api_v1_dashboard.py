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

from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.fleet_snapshot import FleetSnapshot
from app.db.models.fleet_summary import FleetSummary
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services.access_scope import is_restricted

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
async def dashboard_trends_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Every retained daily snapshot, oldest first — whatever the retention
    purge (`app.tasks.jobs.purge_old_fleet_snapshots`) has left in the
    table, with no further filtering here (mirrors the web Dashboard, which
    shows the same unfiltered set once there are at least two).

    An account restricted to specific machine groups gets an empty series,
    the same as the web Dashboard omits the trend chart for one: a snapshot
    is a *stored* fleet-wide total recorded by a background job, so there is
    nothing in it left to narrow — returning it anyway would report the
    whole fleet's size to an account that can't see the whole fleet."""
    if await is_restricted(db, user):
        return {"snapshots": []}
    result = await db.execute(select(FleetSnapshot).order_by(FleetSnapshot.snapshot_date.asc()))
    snapshots = list(result.scalars().all())
    return {"snapshots": [_snapshot_to_dict(s) for s in snapshots]}


def _fleet_summary_to_dict(summary: FleetSummary) -> dict[str, object]:
    return {
        "id": str(summary.id),
        "frequency": summary.frequency,
        "content": summary.content,
        "provider_kind": summary.provider_kind,
        "model_id": summary.model_id,
        "created_at": summary.created_at.isoformat(),
    }


@router.get("/fleet-summary", dependencies=[_view])
async def latest_fleet_summary_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The most recent scheduled fleet summary (`app.tasks.ai_jobs.
    generate_fleet_summary`), or `{"summary": None}` if none has been
    generated yet (the feature is off by default — see Settings' AI tab).

    Same "restricted account sees nothing" reasoning as `/trends` above: a
    summary is unattended, fleet-wide text a background job wrote with no
    per-account scoping possible after the fact."""
    if await is_restricted(db, user):
        return {"summary": None}
    result = await db.execute(
        select(FleetSummary).order_by(FleetSummary.created_at.desc()).limit(1)
    )
    summary = result.scalar_one_or_none()
    return {"summary": _fleet_summary_to_dict(summary) if summary is not None else None}
