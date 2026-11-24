"""Backup & restore -> *Machine configuration* (`/backup/machines`): the
fleet-wide restic repository for configuration backups
(`app.services.config_backup`), every machine's last backup, backing up
several machines at once, and the daily retention run on demand.

Seeing the page needs `machine.view` (machines outside the account's
scope are not listed); changing the repository or running the
maintenance `settings.manage`; starting backups `machine.manage`.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import verify_csrf
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import config_backup
from app.services.access_scope import machines_visible_to
from app.web.flash import read_flash, sign_flash
from app.web.templating import t, templates

router = APIRouter(
    prefix="/backup/machines",
    dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))],
)
need_settings = Depends(require_permission(Permission.SETTINGS_MANAGE))
need_manage = Depends(require_permission(Permission.MACHINE_MANAGE))
PAGE = "/backup/machines"


def _redirect(*, notice: str | None = None, error: str | None = None) -> Response:
    url = PAGE
    if notice:
        url += f"?cb_notice={sign_flash(notice)}"
    elif error:
        url += f"?cb_error={sign_flash(error)}"
    return RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)


def _error_text(request: Request, exc: config_backup.ConfigBackupError) -> str:
    text = t(request, exc.key)
    return f"{text} ({exc.detail})" if exc.detail else text


async def _machines(db: AsyncSession, user: User) -> list[Machine]:
    query = await machines_visible_to(db, user)
    result = await db.execute(query.order_by(Machine.name))
    return list(result.scalars().all())


@router.get("")
async def config_backups_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    settings = await get_or_create_app_settings(db)
    rows = await config_backup.fleet_rows(db, await _machines(db, current_user))
    return templates.TemplateResponse(
        request,
        "backup/machines.html",
        {
            "repo": config_backup.settings_view(settings),
            "default_repository": config_backup.default_location(),
            "rows": rows,
            "max_keep": config_backup.MAX_KEEP,
            "can_settings": current_user.has_permission(Permission.SETTINGS_MANAGE),
            "can_manage": current_user.has_permission(Permission.MACHINE_MANAGE),
            "notice": read_flash(request, "cb_notice"),
            "error": read_flash(request, "cb_error"),
            "csrf_token": request.state.csrf_token,
        },
    )


def _keep(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    if not value.isdecimal():
        return -1
    return int(value)


@router.post("/settings", dependencies=[need_settings, Depends(verify_csrf)])
async def save_config_backup_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    repository: str = Form(""),
    password: str = Form(""),
    environment: str = Form(""),
    change_environment: str = Form(""),
    keep_daily: str = Form(""),
    keep_weekly: str = Form(""),
    keep_monthly: str = Form(""),
) -> Response:
    settings = await get_or_create_app_settings(db)
    if settings.config_backup_password_encrypted is None and not password:
        return _redirect(error=t(request, "config_backup.error.password_required"))
    change = config_backup.SettingsChange(
        repository=repository,
        password=password or None,
        environment=environment if change_environment else None,
        keep_daily=_keep(keep_daily),
        keep_weekly=_keep(keep_weekly),
        keep_monthly=_keep(keep_monthly),
    )
    try:
        changed = config_backup.apply_settings(settings, change)
        repo = config_backup.repository_of(settings)
        if repo is not None and ({"repository", "password", "environment"} & set(changed)):
            await config_backup.ensure_repository(repo)
    except config_backup.ConfigBackupError as exc:
        await db.rollback()
        return _redirect(error=_error_text(request, exc))
    await db.commit()
    if changed:
        await log_event(
            db,
            request=request,
            action="config_backup.settings.update",
            summary="Changed the configuration backup repository settings",
            target_type="settings",
            target_label="config_backup",
            details={
                "changed": changed,
                "repository": settings.config_backup_repository_display
                or config_backup.default_location(),
            },
        )
    return _redirect(notice=t(request, "config_backup.settings_saved"))


@router.post("/run", dependencies=[need_manage, Depends(verify_csrf)])
async def run_config_backups(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Back up the ticked machines, or every visible one."""
    form = await request.form()
    wanted: set[uuid.UUID] = set()
    for raw in form.getlist("machine_id"):
        try:
            wanted.add(uuid.UUID(str(raw)))
        except ValueError:
            continue
    machines = await _machines(db, current_user)
    if form.get("scope") != "all":
        machines = [m for m in machines if m.id in wanted]
    if not machines:
        return _redirect(error=t(request, "config_backup.none_selected"))
    try:
        runs, skipped = await config_backup.queue_backups(
            db, machines, started_by=current_user.username
        )
    except config_backup.ConfigBackupError as exc:
        return _redirect(error=_error_text(request, exc))
    if runs:
        await log_event(
            db,
            request=request,
            action="config_backup.run",
            summary=f"Started configuration backups of {len(runs)} machine(s)",
            target_type="machine",
            details={"machines": len(runs), "skipped": skipped},
        )
    return _redirect(
        notice=t(request, "config_backup.queued_many", count=len(runs), skipped=skipped)
    )


@router.post("/maintenance", dependencies=[need_settings, Depends(verify_csrf)])
async def run_config_backup_maintenance(
    request: Request, db: AsyncSession = Depends(get_db)
) -> Response:
    from app.tasks import config_backup as tasks

    tasks.config_backup_maintenance.delay()
    await log_event(
        db,
        request=request,
        action="config_backup.maintenance.run",
        summary="Started the configuration backup retention and check",
        target_type="settings",
        target_label="config_backup",
    )
    return _redirect(notice=t(request, "config_backup.maintenance_queued"))
