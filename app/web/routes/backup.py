"""Administration → Backup & restore (`/backup`): one page listing every
configuration export/import the app has — machines and groups, scheduled
tasks, roles, notification rules — instead of a button pair on each of
those pages, plus a backup and restore of the **whole application**
(`app.services.full_backup`) for an account that holds every permission.

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
from app.core.csrf import verify_csrf
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import full_backup
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


def _render(
    request: Request, user: User, *, errors: list[str] | None = None, status_code: int = 200
) -> Response:
    return templates.TemplateResponse(
        request,
        "backup/index.html",
        {
            "sections": visible_sections(user),
            "full_backup": can_back_up_everything(user),
            "min_passphrase": full_backup.MIN_PASSPHRASE_LENGTH,
            "csrf_token": request.state.csrf_token,
            "errors": errors or [],
        },
        status_code=status_code,
    )


@router.get("")
async def backup_page(request: Request, user: User = Depends(get_current_user)) -> Response:
    return _render(request, user)


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
        return _render(request, user, errors=[t(request, "backup.full.mismatch")], status_code=422)
    if len(passphrase) < full_backup.MIN_PASSPHRASE_LENGTH:
        return _render(
            request,
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
        return _render(
            request, user, errors=[t(request, "backup.full.confirm_needed")], status_code=422
        )
    path = full_backup.temporary_path()
    try:
        with path.open("wb") as copy:
            shutil.copyfileobj(backup_file.file, copy)
        with path.open("rb") as source:
            manifest = await full_backup.restore_backup(db, source, passphrase)
    except full_backup.BackupError as exc:
        return _render(
            request, user, errors=[t(request, "backup.full.restore_failed", reason=str(exc))],
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
