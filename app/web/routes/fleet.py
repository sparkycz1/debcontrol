"""The machine cards on the Dashboard — every visible machine as a compact
card of its latest readings (see `app.services.fleet_overview`).
Read-only, `machine.view`.

These used to be a page of their own (`/fleet`) with a second, differently
counted summary strip; they now live at the bottom of the Dashboard, under
its one set of counts. `/fleet` redirects there so old bookmarks keep
working, and `GET /fleet/cards` is the fragment the card grid re-fetches
every 60 s."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
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

# The grid renders every visible machine at once; past this many, the
# Machines list (paginated, searchable) is the better tool.
FLEET_PAGE_LIMIT = 500


async def fleet_grid_context(db: AsyncSession, user: User) -> dict[str, object]:
    """What `partials/fleet_grid.html` needs — shared by the Dashboard and
    the grid's own refresh fragment."""
    query = (await machines_visible_to(db, user)).where(Machine.is_active)
    result = await db.execute(query.order_by(Machine.name).limit(FLEET_PAGE_LIMIT + 1))
    machines = list(result.scalars().all())
    return {
        "rows": await build_fleet_overview(db, machines[:FLEET_PAGE_LIMIT]),
        "truncated": len(machines) > FLEET_PAGE_LIMIT,
        "limit": FLEET_PAGE_LIMIT,
    }


@router.get("")
async def fleet_overview() -> Response:
    return RedirectResponse(url="/dashboard#fleet", status_code=308)


@router.get("/cards")
async def fleet_cards(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    return templates.TemplateResponse(
        request, "partials/fleet_grid.html", await fleet_grid_context(db, current_user)
    )
