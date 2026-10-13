"""The status page (`app.services.status_page`): the public page itself,
and the page under Checks where it is set up.

`/status/<token>` is served without a session and outside the network
allowlist (see `app.auth.middleware`); everything else here needs
`machine.manage`.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import status_page
from app.services.access_scope import machines_visible_to
from app.web.templating import templates

public_router = APIRouter(prefix="/status")
router = APIRouter(
    prefix="/checks/status-page",
    dependencies=[Depends(require_permission(Permission.MACHINE_MANAGE))],
)

_NO_STORE = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"}
_MACHINE_CHOICES = 1000


async def _status_or_404(db: AsyncSession, token: str) -> status_page.Status:
    app_settings = await get_or_create_app_settings(db)
    if len(token) > 128 or not status_page.token_matches(app_settings, token):
        # The same answer whether the page is off or the link is wrong.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    return await status_page.cached(db, app_settings)


@public_router.get("/{token}.json", include_in_schema=False)
async def public_status_json(token: str, db: AsyncSession = Depends(get_db)) -> Response:
    current = await _status_or_404(db, token)
    return JSONResponse(current.as_dict(), headers=_NO_STORE)


@public_router.get("/{token}", include_in_schema=False)
async def public_status(
    request: Request, token: str, db: AsyncSession = Depends(get_db)
) -> Response:
    current = await _status_or_404(db, token)
    response = templates.TemplateResponse(
        request,
        "status/public.html",
        {"status": current, "window_days": status_page.WINDOW_DAYS},
    )
    response.headers.update(_NO_STORE)
    return response


@router.get("")
async def status_page_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    checks = await db.execute(select(EndpointCheck).order_by(EndpointCheck.name))
    machines = await machines_visible_to(db, current_user)
    machine_rows = await db.execute(
        machines.with_only_columns(Machine.id, Machine.name)
        .order_by(Machine.name)
        .limit(_MACHINE_CHOICES)
    )
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "status/settings.html",
        {
            "enabled": app_settings.status_page_enabled,
            "title": app_settings.status_page_title or "",
            "token": app_settings.status_page_token,
            "checks": list(checks.scalars().all()),
            "machines": [(row[0], row[1]) for row in machine_rows.all()],
            "chosen_checks": set(status_page.chosen_check_ids(app_settings)),
            "chosen_machines": set(status_page.chosen_machine_ids(app_settings)),
            "window_days": status_page.WINDOW_DAYS,
            "max_items": status_page.MAX_ITEMS,
            "saved": request.query_params.get("saved"),
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


def _uuids(values: list[str]) -> list[str]:
    found: list[str] = []
    for value in values:
        try:
            parsed = str(uuid.UUID(value))
        except ValueError:
            continue
        if parsed not in found:
            found.append(parsed)
    return found[: status_page.MAX_ITEMS]


@router.post("", dependencies=[Depends(verify_csrf)])
async def save_status_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    enabled: bool = Form(False),
    title: str = Form(""),
    check_ids: list[str] = Form(default=[]),
    machine_ids: list[str] = Form(default=[]),
    new_link: bool = Form(False),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    # Only machines this account may see can be put on the page; ones chosen
    # earlier by someone who sees more stay as they are.
    visible = await machines_visible_to(db, current_user)
    visible_ids = {
        str(row[0]) for row in (await db.execute(visible.with_only_columns(Machine.id))).all()
    }
    kept = [
        str(machine_id)
        for machine_id in status_page.chosen_machine_ids(app_settings)
        if str(machine_id) not in visible_ids
    ]
    chosen = [value for value in _uuids(machine_ids) if value in visible_ids]

    app_settings.status_page_enabled = enabled
    app_settings.status_page_title = title.strip()[:120] or None
    app_settings.status_page_check_ids = _uuids(check_ids)
    app_settings.status_page_machine_ids = (kept + chosen)[: status_page.MAX_ITEMS]
    replaced = bool(new_link and app_settings.status_page_token)
    if enabled and (new_link or not app_settings.status_page_token):
        app_settings.status_page_token = status_page.new_token()
    await db.commit()
    status_page.invalidate()
    await log_event(
        db,
        request=request,
        action="status_page.update",
        summary=("Status page turned on or changed" if enabled else "Status page turned off"),
        details={
            "enabled": enabled,
            "checks": len(app_settings.status_page_check_ids or []),
            "machine_count": len(app_settings.status_page_machine_ids or []),
            "link_replaced": replaced,
        },
    )
    return RedirectResponse(
        url="/checks/status-page?saved=1", status_code=status.HTTP_303_SEE_OTHER
    )
