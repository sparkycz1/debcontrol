"""A machine's *Backup* tab: its configuration backups
(`app.services.config_backup`) — the runs, the snapshots in the
repository, what changed between two, and getting a file back.

Seeing runs, snapshots, file names and changes needs `machine.view`;
starting a backup `machine.manage`; anything that hands out a file's
content (download, the whole snapshot, putting a file back on the
machine) `action.terminal`, since `/etc` holds password hashes and keys.
"""

from __future__ import annotations

import uuid
from urllib.parse import quote

from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import config_backup
from app.web.flash import read_flash, sign_flash
from app.web.routes.machines_common import (
    _get_machine_or_404,
    _machine_tabs,
    machines_router,
    need_manage,
)
from app.web.templating import t, templates

router = machines_router()
need_terminal = Depends(require_permission(Permission.ACTION_TERMINAL))


def _page(machine: Machine) -> str:
    return f"/machines/{machine.id}/backup"


def _redirect(url: str, *, notice: str | None = None, error: str | None = None) -> Response:
    if notice:
        url += f"?backup_notice={sign_flash(notice)}"
    elif error:
        url += f"?backup_error={sign_flash(error)}"
    return RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)


def _error_text(request: Request, exc: config_backup.ConfigBackupError) -> str:
    text = t(request, exc.key)
    return f"{text} ({exc.detail})" if exc.detail else text


@router.get("/{machine_id}/backup")
async def backup_tab(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    settings = await get_or_create_app_settings(db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    runs = await config_backup.list_runs(db, machine.id)
    response = templates.TemplateResponse(
        request,
        "machines/backup.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "backup",
            "runs": runs,
            "running": any(run.status in ("pending", "running") for run in runs),
            "repo": config_backup.settings_view(settings),
            "can_manage": current_user.has_permission(Permission.MACHINE_MANAGE),
            "can_restore": current_user.has_permission(Permission.ACTION_TERMINAL),
            "notice": read_flash(request, "backup_notice"),
            "error": read_flash(request, "backup_error"),
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{machine_id}/backup/snapshots")
async def backup_snapshots_panel(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The snapshots in the repository (htmx panel: restic can be slow)."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    error: str | None = None
    snapshots: list[config_backup.Snapshot] = []
    try:
        repo = await config_backup.current_repository(db)
        snapshots = await config_backup.snapshots(repo, machine.id)
    except config_backup.ConfigBackupError as exc:
        error = _error_text(request, exc)
    return templates.TemplateResponse(
        request,
        "machines/_backup_snapshots.html",
        {"machine": machine, "snapshots": snapshots, "error": error},
    )


@router.post("/{machine_id}/backup", dependencies=[need_manage, Depends(verify_csrf)])
async def backup_now(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    try:
        runs, _skipped = await config_backup.queue_backups(
            db, [machine], started_by=current_user.username
        )
    except config_backup.ConfigBackupError as exc:
        return _redirect(_page(machine), error=_error_text(request, exc))
    if not runs:
        return _redirect(_page(machine), error=t(request, "config_backup.not_queued"))
    await log_event(
        db,
        request=request,
        action="config_backup.run",
        summary=f'Started a configuration backup of "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"machines": 1},
    )
    return _redirect(_page(machine), notice=t(request, "config_backup.queued"))


@router.get("/{machine_id}/backup/{snapshot_id}")
async def backup_snapshot(
    request: Request,
    machine_id: uuid.UUID,
    snapshot_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """One snapshot: its files and what changed since the previous one."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    try:
        repo = await config_backup.current_repository(db)
        snapshot, previous = await config_backup.find_snapshot(repo, machine.id, snapshot_id)
        entries = await config_backup.list_entries(repo, snapshot)
        changes = (
            await config_backup.changes_since(repo, previous, snapshot) if previous else None
        )
    except config_backup.ConfigBackupError as exc:
        if exc.key == "config_backup.error.snapshot":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
        return _redirect(_page(machine), error=_error_text(request, exc))
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/backup_snapshot.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "backup",
            "snapshot": snapshot,
            "previous": previous,
            "entries": entries,
            "changes": changes,
            "restore_dir": config_backup.RESTORE_DIR,
            "max_file_mib": config_backup.MAX_FILE_BYTES // (1024 * 1024),
            "can_restore": current_user.has_permission(Permission.ACTION_TERMINAL),
            "notice": read_flash(request, "backup_notice"),
            "error": read_flash(request, "backup_error"),
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{machine_id}/backup/{snapshot_id}/file", dependencies=[need_terminal])
async def backup_download_file(
    request: Request,
    machine_id: uuid.UUID,
    snapshot_id: str,
    path: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    try:
        repo = await config_backup.current_repository(db)
        snapshot, _previous = await config_backup.find_snapshot(repo, machine.id, snapshot_id)
        content = await config_backup.read_file(repo, snapshot, path)
    except config_backup.ConfigBackupError as exc:
        if exc.key in ("config_backup.error.snapshot", "config_backup.error.path"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
        return _redirect(_page(machine), error=_error_text(request, exc))
    await log_event(
        db,
        request=request,
        action="config_backup.file.download",
        summary=f'Downloaded {path} from a configuration backup of "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"snapshot": snapshot.short_id, "path": path},
    )
    name = config_backup.safe_filename(path.rstrip("/").rsplit("/", 1)[-1])
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
            "Cache-Control": "no-store",
        },
    )


@router.get("/{machine_id}/backup/{snapshot_id}/archive", dependencies=[need_terminal])
async def backup_download_archive(
    request: Request,
    machine_id: uuid.UUID,
    snapshot_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The whole snapshot as a tar archive."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    try:
        repo = await config_backup.current_repository(db)
        snapshot, _previous = await config_backup.find_snapshot(repo, machine.id, snapshot_id)
    except config_backup.ConfigBackupError as exc:
        if exc.key == "config_backup.error.snapshot":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
        return _redirect(_page(machine), error=_error_text(request, exc))
    await log_event(
        db,
        request=request,
        action="config_backup.archive.download",
        summary=f'Downloaded a configuration backup of "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"snapshot": snapshot.short_id},
    )
    name = config_backup.archive_name(machine, snapshot)
    return StreamingResponse(
        config_backup.archive_stream(repo, snapshot),
        media_type="application/x-tar",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
            "Cache-Control": "no-store",
        },
    )


@router.post(
    "/{machine_id}/backup/{snapshot_id}/restore",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def backup_restore_file(
    request: Request,
    machine_id: uuid.UUID,
    snapshot_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    path: str = Form(...),
) -> Response:
    """Put one file back on the machine, next to (never over) the original."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    back = f"{_page(machine)}/{quote(snapshot_id)}"
    if not machine.host_key_fingerprint:
        return _redirect(back, error=t(request, "config_backup.error.host_key"))
    try:
        repo = await config_backup.current_repository(db)
        snapshot, _previous = await config_backup.find_snapshot(repo, machine.id, snapshot_id)
        written = await config_backup.restore_to_machine(db, machine, repo, snapshot, path)
    except config_backup.ConfigBackupError as exc:
        if exc.key == "config_backup.error.snapshot":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
        return _redirect(back, error=_error_text(request, exc))
    await log_event(
        db,
        request=request,
        action="config_backup.file.restore",
        summary=f'Restored {path} from a configuration backup onto "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"snapshot": snapshot.short_id, "path": path, "written_to": written},
    )
    return _redirect(back, notice=t(request, "config_backup.restored", path=written))
