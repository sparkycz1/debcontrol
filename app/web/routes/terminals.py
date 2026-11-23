"""**Terminals** (`/terminals`, `action.terminal`): several machines'
terminals on one page, as tabs or side by side in a grid. Each pane is the
machine's own terminal (`terminal_ws.py`, same permission, limits,
recording and audit); this page only lists the machines the account may
open one on and which ones to start with (`?m=<id>` repeated,
`&layout=tabs|grid`). Panes added later are added by the page itself
(`static/js/terminals.js`), so the open sessions keep running.

Not in the REST API: the interactive terminal is one of its documented
exceptions (`api_v1.py`).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services.access_scope import machines_visible_to
from app.web.templating import templates

router = APIRouter(
    dependencies=[
        Depends(require_permission(Permission.MACHINE_VIEW)),
        Depends(require_permission(Permission.ACTION_TERMINAL)),
    ]
)

# More panes than this stop being usable on one screen (and each is an SSH
# session of its own).
MAX_PANES = 8


async def terminal_machines(db: AsyncSession, user: User) -> list[Machine]:
    """Machines `user` may open a terminal on: visible, active, host key
    confirmed."""
    query = await machines_visible_to(db, user)
    result = await db.execute(
        query.where(
            Machine.is_active.is_(True), Machine.host_key_fingerprint.is_not(None)
        ).order_by(Machine.name)
    )
    return list(result.scalars().all())


def chosen(machines: list[Machine], wanted: list[str]) -> list[Machine]:
    """The machines `?m=` names, in that order, only those in `machines`
    (the same machine twice is two terminals); at most `MAX_PANES`."""
    by_id = {m.id: m for m in machines}
    picked: list[Machine] = []
    for raw in wanted:
        try:
            machine = by_id.get(uuid.UUID(raw))
        except ValueError:
            continue
        if machine is not None:
            picked.append(machine)
        if len(picked) >= MAX_PANES:
            break
    return picked


@router.get("/terminals")
async def terminals_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machines = await terminal_machines(db, current_user)
    layout = request.query_params.get("layout")
    return templates.TemplateResponse(
        request,
        "terminals.html",
        {
            "machines": machines,
            "initial": [
                {"id": str(m.id), "name": m.name}
                for m in chosen(machines, request.query_params.getlist("m"))
            ],
            "layout": layout if layout in ("tabs", "grid") else "tabs",
            "max_panes": MAX_PANES,
            "recording": (await get_or_create_app_settings(db)).terminal_recording_enabled,
        },
    )
