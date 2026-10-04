"""REST API for the whole-application backup (`app.services.full_backup`):
`POST /api/v1/backup` returns the same passphrase-encrypted file as
Backup & restore → "Download a full backup", for scheduled off-site
backups. The token's account must hold every permission, as on the web.

`/api/v1/backup/auto` mirrors Backup & restore → "Automatic backups": read
and change the schedule, list the stored backups, download or delete one,
and start a backup now — what an off-site copy job needs.

**Restore is deliberately web-only.** It replaces every account and
token — including the one a script would be calling with — needs a typed
confirmation, and is a disaster-recovery step a human should be watching,
not something to automate.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from app.audit import log_event
from app.auth.dependencies import get_api_token_user
from app.core.app_settings import get_or_create_app_settings
from app.core.security import encrypt_secret
from app.db.models.user import User
from app.db.session import get_db
from app.services import auto_backup, full_backup
from app.tasks import jobs as tasks
from app.web.routes.backup import can_back_up_everything

router = APIRouter(prefix="/api/v1/backup", tags=["backup"])


class FullBackupRequest(BaseModel):
    passphrase: str


@router.post("", response_class=FileResponse)
async def full_backup_api(
    payload: FullBackupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> FileResponse:
    if not can_back_up_everything(user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="A full backup needs an account that holds every permission.",
        )
    if len(payload.passphrase) < full_backup.MIN_PASSPHRASE_LENGTH:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"The passphrase must be at least {full_backup.MIN_PASSPHRASE_LENGTH} characters."
            ),
        )
    path = full_backup.temporary_path()
    with path.open("wb") as destination:
        manifest = await full_backup.write_backup(db, destination, payload.passphrase)
    await log_event(
        db,
        request=request,
        action="backup.full.export",
        summary="Downloaded a full backup of the application (REST API)",
        details={"tables": len(manifest["tables"]), "rows": sum(manifest["tables"].values())},
    )
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=full_backup.backup_filename(),
        background=BackgroundTask(path.unlink, missing_ok=True),
    )


# --- Automatic backups ------------------------------------------------------


class StoredBackupOut(BaseModel):
    name: str
    size: int
    created_at: datetime


class AutoBackupOut(BaseModel):
    enabled: bool
    interval_hours: int
    keep: int
    passphrase_set: bool
    last_at: datetime | None
    last_error: str | None
    backups: list[StoredBackupOut]


class AutoBackupUpdate(BaseModel):
    enabled: bool
    interval_hours: int = Field(
        ge=auto_backup.MIN_INTERVAL_HOURS, le=auto_backup.MAX_INTERVAL_HOURS
    )
    keep: int = Field(ge=auto_backup.MIN_KEEP, le=auto_backup.MAX_KEEP)
    # Write-only: a new passphrase, or omit it to keep the stored one.
    passphrase: str | None = Field(default=None, min_length=full_backup.MIN_PASSPHRASE_LENGTH)


def _require_everything(user: User) -> None:
    if not can_back_up_everything(user):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Backups need an account that holds every permission.",
        )


async def _auto_backup_out(db: AsyncSession) -> dict[str, Any]:
    app_settings = await get_or_create_app_settings(db)
    return {
        "enabled": app_settings.auto_backup_enabled,
        "interval_hours": app_settings.auto_backup_interval_hours,
        "keep": app_settings.auto_backup_keep,
        "passphrase_set": app_settings.auto_backup_passphrase_encrypted is not None,
        "last_at": app_settings.auto_backup_last_at,
        "last_error": app_settings.auto_backup_last_error,
        "backups": [
            {"name": b.name, "size": b.size, "created_at": b.created_at}
            for b in auto_backup.list_backups()
        ],
    }


@router.get("/auto", response_model=AutoBackupOut)
async def get_auto_backup_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> dict[str, Any]:
    _require_everything(user)
    return await _auto_backup_out(db)


@router.put("/auto", response_model=AutoBackupOut)
async def update_auto_backup_api(
    payload: AutoBackupUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    _require_everything(user)
    app_settings = await get_or_create_app_settings(db)
    if (
        payload.enabled
        and not payload.passphrase
        and not app_settings.auto_backup_passphrase_encrypted
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Automatic backups need a passphrase before they can be switched on.",
        )
    app_settings.auto_backup_enabled = payload.enabled
    app_settings.auto_backup_interval_hours = payload.interval_hours
    app_settings.auto_backup_keep = payload.keep
    if payload.passphrase:
        app_settings.auto_backup_passphrase_encrypted = encrypt_secret(payload.passphrase)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="backup.auto.update",
        summary="Changed the automatic backup settings (REST API)",
        details={
            "enabled": payload.enabled,
            "interval_hours": payload.interval_hours,
            "keep": payload.keep,
            "passphrase_changed": bool(payload.passphrase),
        },
    )
    return await _auto_backup_out(db)


@router.post("/auto/run", status_code=status.HTTP_202_ACCEPTED)
async def run_auto_backup_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> dict[str, bool]:
    """Queue a backup now. It shows up in `GET /auto` once written."""
    _require_everything(user)
    app_settings = await get_or_create_app_settings(db)
    if not app_settings.auto_backup_passphrase_encrypted:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Automatic backups have no passphrase yet.",
        )
    tasks.run_due_app_backup.delay(True)
    return {"queued": True}


@router.get("/auto/files/{name}", response_class=FileResponse)
async def download_stored_backup_api(
    name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> FileResponse:
    _require_everything(user)
    path = auto_backup.backup_path(name)
    if path is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such backup.")
    await log_event(
        db,
        request=request,
        action="backup.auto.download",
        summary=f"Downloaded the stored backup {name} (REST API)",
        details={"file": name},
    )
    return FileResponse(path, media_type="application/octet-stream", filename=name)


@router.delete("/auto/files/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_stored_backup_api(
    name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    _require_everything(user)
    if not auto_backup.delete_backup(name):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such backup.")
    await log_event(
        db,
        request=request,
        action="backup.auto.delete",
        summary=f"Deleted the stored backup {name} (REST API)",
        details={"file": name},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
