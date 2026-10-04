"""Administration → Backup & restore (`/backup`): one page listing every
configuration export/import the app has — machines and groups, scheduled
tasks, roles, notification rules — instead of a button pair on each of
those pages, plus a backup and restore of the **whole application**
(`app.services.full_backup`) for an account that holds every permission,
and scheduled copies of that backup kept on the data volume
(`app.services.auto_backup`).

The page itself only links; each export/import keeps its own route and its
own permission (the same one it always had), and a section is shown only
to an account that could use at least its export."""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.auth.sessions import clear_session_cookie
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import verify_csrf
from app.core.security import encrypt_secret
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import auto_backup, full_backup
from app.tasks import jobs as tasks
from app.web.flash import sign_flash
from app.web.templating import t, templates

router = APIRouter(prefix="/backup")


@dataclass(frozen=True)
class BackupSection:
    key: str
    view_permission: Permission
    manage_permission: Permission
    # (label key, href) pairs.
    exports: tuple[tuple[str, str], ...]
    import_href: str


SECTIONS: tuple[BackupSection, ...] = (
    BackupSection(
        key="machines",
        view_permission=Permission.MACHINE_VIEW,
        manage_permission=Permission.MACHINE_MANAGE,
        exports=(
            ("backup.export_json", "/machines/config/export?format=json"),
            ("backup.export_csv", "/machines/config/export?format=csv"),
        ),
        import_href="/machines/config/import",
    ),
    BackupSection(
        key="scheduling",
        view_permission=Permission.SCHEDULING_VIEW,
        manage_permission=Permission.SCHEDULING_MANAGE,
        exports=(("backup.export_json", "/scheduling/config/export"),),
        import_href="/scheduling/config/import",
    ),
    BackupSection(
        key="roles",
        view_permission=Permission.USER_MANAGE,
        manage_permission=Permission.USER_MANAGE,
        exports=(("backup.export_json", "/roles/config/export"),),
        import_href="/roles/config/import",
    ),
    BackupSection(
        key="notifications",
        view_permission=Permission.NOTIFICATION_VIEW,
        manage_permission=Permission.NOTIFICATION_MANAGE,
        exports=(("backup.export_yaml", "/notifications/rules/export"),),
        import_href="/notifications/rules/import",
    ),
)


def visible_sections(user: User) -> list[BackupSection]:
    return [s for s in SECTIONS if user.has_permission(s.view_permission)]


def can_back_up_everything(user: User) -> bool:
    """A full backup holds every account, credential and secret, and a
    restore replaces all of them — so only an account that already holds
    every permission may do either."""
    return all(user.has_permission(permission) for permission in Permission)


async def _render(
    request: Request,
    db: AsyncSession,
    user: User,
    *,
    errors: list[str] | None = None,
    status_code: int = 200,
) -> Response:
    full = can_back_up_everything(user)
    return templates.TemplateResponse(
        request,
        "backup/index.html",
        {
            "sections": visible_sections(user),
            "full_backup": full,
            "min_passphrase": full_backup.MIN_PASSPHRASE_LENGTH,
            "csrf_token": request.state.csrf_token,
            "errors": errors or [],
            "notice": request.query_params.get("notice", ""),
            "app_settings": await get_or_create_app_settings(db) if full else None,
            "stored_backups": auto_backup.list_backups() if full else [],
            "auto_backup_limits": auto_backup,
        },
        status_code=status_code,
    )


@router.get("")
async def backup_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    return await _render(request, db, user)


def _require_everything(user: User) -> None:
    if not can_back_up_everything(user):
        raise HTTPException(status_code=403, detail="Missing permission.")


@router.post("/full", dependencies=[Depends(verify_csrf)])
async def download_full_backup(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    passphrase: str = Form(""),
    passphrase_confirm: str = Form(""),
) -> Response:
    """The whole application as one passphrase-encrypted file."""
    _require_everything(user)
    if passphrase != passphrase_confirm:
        return await _render(
            request, db, user, errors=[t(request, "backup.full.mismatch")], status_code=422
        )
    if len(passphrase) < full_backup.MIN_PASSPHRASE_LENGTH:
        return await _render(
            request,
            db,
            user,
            errors=[t(request, "backup.full.too_short", count=full_backup.MIN_PASSPHRASE_LENGTH)],
            status_code=422,
        )
    path = full_backup.temporary_path()
    with path.open("wb") as destination:
        manifest = await full_backup.write_backup(db, destination, passphrase)
    await log_event(
        db,
        request=request,
        action="backup.full.export",
        summary="Downloaded a full backup of the application",
        details={"tables": len(manifest["tables"]), "rows": sum(manifest["tables"].values())},
    )
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=full_backup.backup_filename(),
        background=BackgroundTask(path.unlink, missing_ok=True),
    )


@router.post("/full/restore", dependencies=[Depends(verify_csrf)])
async def restore_full_backup(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    backup_file: UploadFile = File(...),
    passphrase: str = Form(""),
    confirm: str = Form(""),
) -> Response:
    """Replaces the whole application with an uploaded full backup, then
    signs everyone out (every account and session comes from the backup)."""
    _require_everything(user)
    if confirm.strip() != "RESTORE":
        return await _render(
            request, db, user, errors=[t(request, "backup.full.confirm_needed")], status_code=422
        )
    path = full_backup.temporary_path()
    try:
        with path.open("wb") as copy:
            shutil.copyfileobj(backup_file.file, copy)
        with path.open("rb") as source:
            manifest = await full_backup.restore_backup(db, source, passphrase)
    except full_backup.BackupError as exc:
        return await _render(
            request, db, user, errors=[t(request, "backup.full.restore_failed", reason=str(exc))],
            status_code=422,
        )
    finally:
        path.unlink(missing_ok=True)

    await log_event(
        db,
        request=request,
        action="backup.full.restore",
        summary=f"Restored the application from a full backup made {manifest.get('created_at')}",
        details={
            "backup_app_version": manifest.get("app_version"),
            "backup_created_at": manifest.get("created_at"),
            "rows": sum(manifest.get("tables", {}).values()),
        },
    )
    notice = sign_flash(t(request, "backup.full.restored"))
    response = RedirectResponse(url=f"/login?notice={notice}", status_code=303)
    clear_session_cookie(response)
    return response


# --- Automatic backups (app.services.auto_backup) ---------------------------


def parse_auto_backup_numbers(interval_hours: str, keep: str) -> tuple[int, int]:
    """The two numbers of the automatic-backup form, range-checked. Raises
    ValueError with a message for the user."""
    try:
        interval, kept = int(interval_hours), int(keep)
    except ValueError:
        raise ValueError("The interval and the number of backups must be whole numbers.") from None
    if not auto_backup.MIN_INTERVAL_HOURS <= interval <= auto_backup.MAX_INTERVAL_HOURS:
        raise ValueError(
            f"The interval must be {auto_backup.MIN_INTERVAL_HOURS} to "
            f"{auto_backup.MAX_INTERVAL_HOURS} hours."
        )
    if not auto_backup.MIN_KEEP <= kept <= auto_backup.MAX_KEEP:
        raise ValueError(
            f"The number of backups to keep must be {auto_backup.MIN_KEEP} to "
            f"{auto_backup.MAX_KEEP}."
        )
    return interval, kept


@router.post("/auto", dependencies=[Depends(verify_csrf)])
async def save_auto_backup(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    enabled: str = Form(""),
    interval_hours: str = Form("24"),
    keep: str = Form("7"),
    passphrase: str = Form(""),
) -> Response:
    _require_everything(user)
    app_settings = await get_or_create_app_settings(db)
    try:
        interval, kept = parse_auto_backup_numbers(interval_hours, keep)
    except ValueError as exc:
        return await _render(request, db, user, errors=[str(exc)], status_code=422)
    if passphrase and len(passphrase) < full_backup.MIN_PASSPHRASE_LENGTH:
        return await _render(
            request,
            db,
            user,
            errors=[t(request, "backup.full.too_short", count=full_backup.MIN_PASSPHRASE_LENGTH)],
            status_code=422,
        )
    if enabled and not passphrase and not app_settings.auto_backup_passphrase_encrypted:
        return await _render(
            request, db, user, errors=[t(request, "backup.auto.passphrase_needed")], status_code=422
        )
    app_settings.auto_backup_enabled = bool(enabled)
    app_settings.auto_backup_interval_hours = interval
    app_settings.auto_backup_keep = kept
    if passphrase:
        app_settings.auto_backup_passphrase_encrypted = encrypt_secret(passphrase)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="backup.auto.update",
        summary="Changed the automatic backup settings",
        details={
            "enabled": bool(enabled),
            "interval_hours": interval,
            "keep": kept,
            "passphrase_changed": bool(passphrase),
        },
    )
    return RedirectResponse(url="/backup?notice=saved", status_code=303)


@router.post("/auto/run", dependencies=[Depends(verify_csrf)])
async def run_auto_backup_now(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """Queue a backup now; the page shows it once the worker has written it."""
    _require_everything(user)
    app_settings = await get_or_create_app_settings(db)
    if not app_settings.auto_backup_passphrase_encrypted:
        return await _render(
            request, db, user, errors=[t(request, "backup.auto.passphrase_needed")], status_code=422
        )
    tasks.run_due_app_backup.delay(True)
    return RedirectResponse(url="/backup?notice=started", status_code=303)


@router.get("/auto/files/{name}")
async def download_stored_backup(
    name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    _require_everything(user)
    path = auto_backup.backup_path(name)
    if path is None:
        raise HTTPException(status_code=404, detail="No such backup.")
    await log_event(
        db,
        request=request,
        action="backup.auto.download",
        summary=f"Downloaded the stored backup {name}",
        details={"file": name},
    )
    return FileResponse(path, media_type="application/octet-stream", filename=name)


@router.post("/auto/files/{name}/delete", dependencies=[Depends(verify_csrf)])
async def delete_stored_backup(
    name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    _require_everything(user)
    if not auto_backup.delete_backup(name):
        raise HTTPException(status_code=404, detail="No such backup.")
    await log_event(
        db,
        request=request,
        action="backup.auto.delete",
        summary=f"Deleted the stored backup {name}",
        details={"file": name},
    )
    return RedirectResponse(url="/backup?notice=deleted", status_code=303)
