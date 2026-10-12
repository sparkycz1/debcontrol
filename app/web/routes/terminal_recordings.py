"""Audit → Terminal recordings: the list of recorded browser terminal
sessions and the page that replays one. See
`app.db.models.terminal_recording` for what a recording is.

Everything here needs `audit.view` — a recording is evidence of what an
administrator did, like the audit log, not part of managing the machine.
Fetching a recording's content is itself audited
(`terminal.recording.view`): a recording can show whatever the session
printed.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import require_permission
from app.core.app_settings import get_or_create_app_settings
from app.db.models.role import Permission
from app.db.models.terminal_recording import TerminalRecording
from app.db.session import get_db
from app.services import terminal_recording
from app.web.templating import templates

router = APIRouter(
    prefix="/audit/terminal-recordings",
    dependencies=[Depends(require_permission(Permission.AUDIT_VIEW))],
)


async def _get_or_404(db: AsyncSession, recording_id: uuid.UUID) -> TerminalRecording:
    recording = await db.get(TerminalRecording, recording_id)
    if recording is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found.")
    return recording


@router.get("")
async def list_terminal_recordings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    machine_id: uuid.UUID | None = None,
    page: int = 1,
) -> Response:
    page = max(page, 1)
    recordings, has_older = await terminal_recording.list_recordings(
        db, machine_id=machine_id, page=page
    )
    app_settings = await get_or_create_app_settings(db)
    return templates.TemplateResponse(
        request,
        "audit/terminal_recordings.html",
        {
            "recordings": recordings,
            "machine_id": machine_id,
            "page": page,
            "has_older": has_older,
            "recording_enabled": app_settings.terminal_recording_enabled,
            "retention_days": app_settings.terminal_recording_retention_days,
        },
    )


@router.get("/{recording_id}")
async def terminal_recording_page(
    request: Request, recording_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    """The player's page. The recording itself is fetched by the page's
    script from `/cast` below, which is where watching it is audited."""
    recording = await _get_or_404(db, recording_id)
    return templates.TemplateResponse(
        request, "audit/terminal_recording.html", {"recording": recording}
    )


@router.get("/{recording_id}/cast")
async def terminal_recording_cast(
    request: Request, recording_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    recording = await _get_or_404(db, recording_id)
    cast = terminal_recording.parse_cast(terminal_recording.unpack(recording.data_encrypted))
    await log_event(
        db,
        request=request,
        action="terminal.recording.view",
        summary=(
            f'Watched the recording of "{recording.username}"\'s terminal session '
            f'on "{recording.machine_name}"'
        ),
        target_type="machine" if recording.machine_id else None,
        target_id=recording.machine_id,
        target_label=recording.machine_name,
        details={"recording_id": str(recording.id)},
    )
    # Never cached: the content is as sensitive as anything in the app.
    return JSONResponse(cast, headers={"Cache-Control": "no-store"})
