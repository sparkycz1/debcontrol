"""The Fleet page — every visible machine as a compact card of its latest
readings (see `app.services.fleet_overview`). Read-only, `machine.view`.
The grid refreshes itself every 60 s (htmx `hx-select` against this same
page — no separate fragment endpoint)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, require_permission
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services.access_scope import machines_visible_to
from app.services.fleet_overview import build_fleet_overview
from app.web.templating import templates

router = APIRouter(
    prefix="/fleet", dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))]
)

# The page renders every visible machine at once; past this many, the
# Machines list (paginated, searchable) is the better tool.
FLEET_PAGE_LIMIT = 500


@router.get("")
async def fleet_overview(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    query = (await machines_visible_to(db, current_user)).where(Machine.is_active)
    result = await db.execute(query.order_by(Machine.name).limit(FLEET_PAGE_LIMIT + 1))
    machines = list(result.scalars().all())
    truncated = len(machines) > FLEET_PAGE_LIMIT
    rows = await build_fleet_overview(db, machines[:FLEET_PAGE_LIMIT])
    return templates.TemplateResponse(
        request,
        "fleet/index.html",
        {
            "rows": rows,
            "truncated": truncated,
            "limit": FLEET_PAGE_LIMIT,
            "counts": {
                "total": len(rows),
                "online": sum(1 for r in rows if r.is_reachable),
                "offline": sum(1 for r in rows if r.is_reachable is False),
                "attention": sum(1 for r in rows if r.needs_attention),
            },
        },
    )
