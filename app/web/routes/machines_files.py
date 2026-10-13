"""The "Watched files" page of a machine (`app.services.watched_files`).

Everyone who can see the machine sees which files are watched and when
they last changed. The diff itself — file content — and the list of paths
are for `machine.manage`.
"""

from __future__ import annotations

import asyncio
import uuid

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import watched_files
from app.tasks import jobs as tasks
from app.web.flash import read_flash, sign_flash
from app.web.routes.machines_common import (
    _get_machine_or_404,
    _machine_tabs,
    machines_router,
    need_manage,
)
from app.web.templating import t, templates

router = machines_router()


@router.get("/{machine_id}/files")
async def watched_files_page(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    diff: uuid.UUID | None = None,
    paths_text: str | None = None,
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    rows = await watched_files.list_files(db, machine.id)
    can_manage = current_user.has_permission(Permission.MACHINE_MANAGE)
    shown = next((row for row in rows if row.id == diff), None) if can_manage and diff else None
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/files.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "overview",
            "files": rows,
            "can_manage": can_manage,
            "diff_file": shown,
            "diff_lines": watched_files.diff_of(shown) if shown is not None else [],
            "paths_text": "\n".join(row.path for row in rows),
            "max_files": watched_files.MAX_FILES,
            "max_kib": watched_files.MAX_BYTES // 1024,
            "notice": read_flash(request, "files_notice"),
            "error": read_flash(request, "files_error"),
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/files", dependencies=[need_manage, Depends(verify_csrf)])
async def save_watched_files(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    paths: str = Form(""),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    base = f"/machines/{machine.id}/files"
    try:
        wanted = watched_files.parse_paths(paths)
    except watched_files.WatchedFilesError as exc:
        return RedirectResponse(
            url=f"{base}?files_error={sign_flash(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    added, removed = await watched_files.set_paths(db, machine, wanted)
    if added or removed:
        await log_event(
            db,
            request=request,
            action="machine.watched_files.update",
            summary=f'Changed the watched files of "{machine.name}"',
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
            details={"file": wanted, "added": added, "removed": removed},
        )
    if wanted and machine.host_key_fingerprint:
        tasks.check_watched_files.delay(str(machine.id))
    notice = t(request, "watched_files.saved")
    return RedirectResponse(
        url=f"{base}?files_notice={sign_flash(notice)}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{machine_id}/files/check", dependencies=[need_manage, Depends(verify_csrf)])
async def check_watched_files_now(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Read the files now and wait for the answer."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    base = f"/machines/{machine.id}/files"
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint first.",
        )
    app_settings = await get_or_create_app_settings(db)
    error: str | None = None
    changed = 0
    try:
        result = await asyncio.to_thread(
            tasks.check_watched_files.delay(str(machine.id)).get,
            timeout=app_settings.ssh_connect_timeout + 90,
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
        elif isinstance(result, dict):
            changed = int(result.get("changed") or 0)
    except CeleryTimeoutError:
        error = t(request, "common.error.command_timeout")
    if error is not None:
        query = f"files_error={sign_flash(error)}"
    else:
        query = "files_notice=" + sign_flash(
            t(request, "watched_files.checked_result", count=changed)
        )
    return RedirectResponse(url=f"{base}?{query}", status_code=status.HTTP_303_SEE_OTHER)
