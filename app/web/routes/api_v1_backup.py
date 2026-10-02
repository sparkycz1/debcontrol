"""REST API for the whole-application backup (`app.services.full_backup`):
`POST /api/v1/backup` returns the same passphrase-encrypted file as
Backup & restore → "Download a full backup", for scheduled off-site
backups. The token's account must hold every permission, as on the web.

**Restore is deliberately web-only.** It replaces every account and
token — including the one a script would be calling with — needs a typed
confirmation, and is a disaster-recovery step a human should be watching,
not something to automate.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from app.audit import log_event
from app.auth.dependencies import get_api_token_user
from app.db.models.user import User
from app.db.session import get_db
from app.services import full_backup
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
