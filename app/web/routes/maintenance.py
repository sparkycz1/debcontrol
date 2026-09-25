"""Maintenance windows (`/notifications/maintenance`) — scheduled time
ranges during which notifications about the chosen machines/groups are
muted. See `app.db.models.maintenance_window` for the semantics and
`app.services.maintenance_windows` for the matching; the REST twin is in
`app/web/routes/api_v1_notifications.py`. Part of Notifications, with its
permissions: `notification.view` to see, `notification.manage` to change.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.maintenance_window import MAX_WINDOW_DURATION, MaintenanceWindowSave
from app.services.maintenance_windows import apply_window_data, window_state
from app.web.templating import parse_local_input, t, templates, to_local_input

router = APIRouter(
    prefix="/notifications/maintenance",
    dependencies=[Depends(require_permission(Permission.NOTIFICATION_VIEW))],
)
_manage = Depends(require_permission(Permission.NOTIFICATION_MANAGE))

# How many ended windows the list keeps showing.
_PAST_WINDOWS_SHOWN = 20


def window_summary(window: MaintenanceWindow) -> str:
    """English scope description for audit summaries."""
    if window.all_machines:
        return "all machines"
    parts = [f"group {g.name}" for g in window.machine_groups]
    parts += [m.name for m in window.machines]
    return ", ".join(parts)


async def _get_window_or_404(window_id: uuid.UUID, db: AsyncSession) -> MaintenanceWindow:
    window = await db.get(MaintenanceWindow, window_id)
    if window is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Maintenance window not found.")
    return window


async def _form_page(
    request: Request,
    db: AsyncSession,
    *,
    window: MaintenanceWindow | None,
    form: dict[str, Any],
    errors: list[str],
    status_code: int = status.HTTP_200_OK,
) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "notifications/maintenance_form.html",
        {
            "window": window,
            "form": form,
            "errors": errors,
            "all_groups": list(
                (await db.execute(select(MachineGroup).order_by(MachineGroup.name))).scalars()
            ),
            "all_machines": list(
                (await db.execute(select(Machine).order_by(Machine.name))).scalars()
            ),
            "csrf_token": csrf_token,
        },
        status_code=status_code,
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


def _form_of(window: MaintenanceWindow) -> dict[str, Any]:
    return {
        "name": window.name,
        "reason": window.reason or "",
        "starts_at": to_local_input(window.starts_at),
        "ends_at": to_local_input(window.ends_at),
        "all_machines": window.all_machines,
        "machine_group_ids": [str(g.id) for g in window.machine_groups],
        "machine_ids": [str(m.id) for m in window.machines],
    }


async def _parse_form(request: Request) -> tuple[dict[str, Any], MaintenanceWindowSave | None, str]:
    raw = await request.form()
    form: dict[str, Any] = {
        "name": str(raw.get("name", "")),
        "reason": str(raw.get("reason", "")),
        "starts_at": str(raw.get("starts_at", "")),
        "ends_at": str(raw.get("ends_at", "")),
        "all_machines": bool(raw.get("all_machines")),
        "machine_group_ids": [str(v) for v in raw.getlist("machine_group_ids")],
        "machine_ids": [str(v) for v in raw.getlist("machine_ids")],
    }
    try:
        starts_at = parse_local_input(form["starts_at"])
        ends_at = parse_local_input(form["ends_at"])
    except ValueError:
        return form, None, t(request, "maintenance.error.dates")
    # The schema enforces the same rules; checked here first only to word
    # the common mistakes in the viewer's language.
    if not form["name"].strip():
        return form, None, t(request, "maintenance.error.name")
    if ends_at <= starts_at:
        return form, None, t(request, "maintenance.error.order")
    if ends_at - starts_at > MAX_WINDOW_DURATION:
        return form, None, t(request, "maintenance.error.too_long")
    if not (form["all_machines"] or form["machine_group_ids"] or form["machine_ids"]):
        return form, None, t(request, "maintenance.error.scope")
    try:
        payload = MaintenanceWindowSave(
            name=form["name"],
            reason=form["reason"],
            starts_at=starts_at,
            ends_at=ends_at,
            all_machines=form["all_machines"],
            machine_group_ids=form["machine_group_ids"],
            machine_ids=form["machine_ids"],
        )
    except ValidationError as exc:
        message = str(exc.errors()[0].get("msg", "")).removeprefix("Value error, ")
        return form, None, message
    return form, payload, ""


@router.get("")
async def list_windows(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    now = datetime.now(UTC)
    windows = list(
        (
            await db.execute(select(MaintenanceWindow).order_by(MaintenanceWindow.starts_at))
        ).scalars()
    )
    active = [w for w in windows if window_state(w, now) == "active"]
    upcoming = [w for w in windows if window_state(w, now) == "upcoming"]
    ended = [w for w in windows if window_state(w, now) == "ended"][-_PAST_WINDOWS_SHOWN:][::-1]
    return templates.TemplateResponse(
        request,
        "notifications/maintenance.html",
        {
            "active": active,
            "upcoming": upcoming,
            "ended": ended,
            "csrf_token": request.state.csrf_token,
        },
    )


@router.get("/new")
async def new_window_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    return await _form_page(
        request,
        db,
        window=None,
        form={"starts_at": to_local_input(now), "machine_group_ids": [], "machine_ids": []},
        errors=[],
    )


@router.post("", dependencies=[_manage, Depends(verify_csrf)])
async def create_window(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    form, payload, error = await _parse_form(request)
    if payload is None:
        return await _form_page(
            request, db, window=None, form=form, errors=[error],
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    window = MaintenanceWindow(created_by=current_user.username)
    await apply_window_data(db, window, payload)
    db.add(window)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="maintenance_window.create",
        summary=f'Scheduled maintenance window "{window.name}" ({window_summary(window)})',
        target_type="maintenance_window",
        target_id=window.id,
        target_label=window.name,
        details={
            "starts_at": window.starts_at.isoformat(),
            "ends_at": window.ends_at.isoformat(),
            "scope": window_summary(window),
        },
    )
    return RedirectResponse(
        url="/notifications/maintenance", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/{window_id}/edit")
async def edit_window_form(
    request: Request, window_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    window = await _get_window_or_404(window_id, db)
    return await _form_page(request, db, window=window, form=_form_of(window), errors=[])


@router.post("/{window_id}/edit", dependencies=[_manage, Depends(verify_csrf)])
async def update_window(
    request: Request, window_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    window = await _get_window_or_404(window_id, db)
    form, payload, error = await _parse_form(request)
    if payload is None:
        return await _form_page(
            request, db, window=window, form=form, errors=[error],
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
    await apply_window_data(db, window, payload)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="maintenance_window.update",
        summary=f'Updated maintenance window "{window.name}" ({window_summary(window)})',
        target_type="maintenance_window",
        target_id=window.id,
        target_label=window.name,
        details={
            "starts_at": window.starts_at.isoformat(),
            "ends_at": window.ends_at.isoformat(),
            "scope": window_summary(window),
        },
    )
    return RedirectResponse(
        url="/notifications/maintenance", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{window_id}/end", dependencies=[_manage, Depends(verify_csrf)])
async def end_window_now(
    request: Request, window_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    """Finish an active window early (or cancel an upcoming one) — kept in
    the list as ended, rather than deleted, so it's still visible what was
    muted and when."""
    window = await _get_window_or_404(window_id, db)
    now = datetime.now(UTC)
    if window_state(window, now) != "ended":
        if window_state(window, now) == "upcoming":
            window.starts_at = now
        window.ends_at = now
        await db.commit()
        await log_event(
            db,
            request=request,
            action="maintenance_window.end",
            summary=f'Ended maintenance window "{window.name}" early',
            target_type="maintenance_window",
            target_id=window.id,
            target_label=window.name,
        )
    return RedirectResponse(
        url="/notifications/maintenance", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{window_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_window(
    request: Request, window_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    window = await _get_window_or_404(window_id, db)
    name = window.name
    await db.delete(window)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="maintenance_window.delete",
        summary=f'Deleted maintenance window "{name}"',
        target_type="maintenance_window",
        target_id=window_id,
        target_label=name,
    )
    return RedirectResponse(
        url="/notifications/maintenance", status_code=status.HTTP_303_SEE_OTHER
    )
