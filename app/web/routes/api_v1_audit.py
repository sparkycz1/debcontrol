"""REST API for the audit log — mirrors `app/web/routes/audit.py` (list/
filter, CSV/JSON export)."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event, verify_chain
from app.auth.dependencies import require_api_permission
from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.models.role import Permission
from app.db.models.terminal_recording import TerminalRecording
from app.db.session import get_db
from app.services import terminal_recording
from app.web.audit_search import apply_audit_filters
from app.web.routes.audit import _EXPORT_FIELDS, _csv_safe, _entry_to_export_row

router = APIRouter(prefix="/api/v1/audit")

_view = Depends(require_api_permission(Permission.AUDIT_VIEW))
# Same permission the Settings page's "Verify now" button needs.
_verify = Depends(require_api_permission(Permission.SETTINGS_MANAGE))

_PAGE_SIZE = 50


def _entry_to_dict(entry: AuditLogEntry) -> dict[str, Any]:
    return {
        "id": str(entry.id),
        "sequence": entry.sequence,
        "created_at": entry.created_at.isoformat(),
        "actor": entry.actor,
        "ip_address": entry.ip_address,
        "geo_country": entry.geo_country,
        "geo_country_code": entry.geo_country_code,
        "geo_city": entry.geo_city,
        "geo_latitude": entry.geo_latitude,
        "geo_longitude": entry.geo_longitude,
        "action": entry.action,
        "outcome": entry.outcome.value,
        "summary": entry.summary,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "target_label": entry.target_label,
        "details": entry.details,
    }


@router.get("", dependencies=[_view])
async def list_audit_log_api(
    db: AsyncSession = Depends(get_db),
    q: str = "",
    outcome: str = "",
    target_type: str = "",
    target_id: str = "",
    page: int = 1,
) -> dict[str, object]:
    page = max(page, 1)
    query = apply_audit_filters(
        select(AuditLogEntry), q=q, outcome=outcome, target_type=target_type, target_id=target_id
    )

    offset = (page - 1) * _PAGE_SIZE
    result = await db.execute(
        query.order_by(AuditLogEntry.created_at.desc()).offset(offset).limit(_PAGE_SIZE + 1)
    )
    entries = list(result.scalars().all())
    has_older = len(entries) > _PAGE_SIZE
    entries = entries[:_PAGE_SIZE]
    return {
        "entries": [_entry_to_dict(e) for e in entries],
        "page": page,
        "has_older": has_older,
    }


@router.get("/export", dependencies=[_view])
async def export_audit_log_api(
    request: Request,
    db: AsyncSession = Depends(get_db),
    q: str = "",
    outcome: str = "",
    target_type: str = "",
    target_id: str = "",
    format: str = "csv",
) -> Response:
    query = apply_audit_filters(
        select(AuditLogEntry), q=q, outcome=outcome, target_type=target_type, target_id=target_id
    )
    result = await db.execute(query.order_by(AuditLogEntry.created_at.asc()))
    entries = list(result.scalars().all())

    await log_event(
        db,
        request=request,
        action="audit_log.export",
        summary=f"Exported {len(entries)} audit log entry/entries as {format}",
        details={"count": len(entries), "format": format, "q": q, "outcome": outcome},
    )

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    rows = [_entry_to_export_row(e) for e in entries]

    if format == "json":
        return Response(
            content=json.dumps(rows, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="audit-log-{timestamp}.json"'},
        )

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_EXPORT_FIELDS)
    writer.writeheader()
    writer.writerows({k: _csv_safe(v) for k, v in row.items()} for row in rows)
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="audit-log-{timestamp}.csv"'},
    )


@router.post("/verify", dependencies=[_verify])
async def verify_audit_chain_api(
    request: Request, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    """Recompute the audit log's hash chain now — Settings → Security's
    "Verify now", with the same `settings.manage` permission. `ok` is
    false (and `broken_at_sequence` set) if an entry was altered or
    removed. Recorded as `audit_log.verify` like the button."""
    result = await verify_chain(db)
    await log_event(
        db,
        request=request,
        action="audit_log.verify",
        summary=f"Verified audit log hash chain: {result.message}",
        outcome=AuditOutcome.SUCCESS if result.ok else AuditOutcome.FAILURE,
        details={"checked": result.checked, "broken_at_sequence": result.broken_at_sequence},
    )
    return {
        "ok": result.ok,
        "checked": result.checked,
        "broken_at_sequence": result.broken_at_sequence,
        "message": result.message,
    }


# --- Terminal recordings (app.services.terminal_recording) -----------------

recordings_router = APIRouter(prefix="/api/v1/terminal-recordings")


@recordings_router.get("", dependencies=[_view])
async def list_terminal_recordings_api(
    db: AsyncSession = Depends(get_db),
    machine_id: uuid.UUID | None = None,
    page: int = 1,
) -> dict[str, Any]:
    """Recorded browser terminal sessions, newest first, 50 per page —
    who, on which machine, when and for how long. `audit.view`."""
    recordings, has_older = await terminal_recording.list_recordings(
        db, machine_id=machine_id, page=page
    )
    return {
        "recordings": [terminal_recording.as_dict(r) for r in recordings],
        "page": max(page, 1),
        "has_older": has_older,
    }


@recordings_router.get("/{recording_id}", dependencies=[_view])
async def get_terminal_recording_api(
    recording_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    """One recording with its content: `cols`, `rows` and `events`, each
    `[seconds, "o" | "r", text]` (output, or a resize as "COLSxROWS").
    Reading it is audited as `terminal.recording.view`, like watching it."""
    recording = await db.get(TerminalRecording, recording_id)
    if recording is None:
        raise HTTPException(status_code=404, detail="Recording not found.")
    cast = terminal_recording.parse_cast(terminal_recording.unpack(recording.data_encrypted))
    await log_event(
        db,
        request=request,
        action="terminal.recording.view",
        summary=(
            f'Read the recording of "{recording.username}"\'s terminal session '
            f'on "{recording.machine_name}"'
        ),
        target_type="machine" if recording.machine_id else None,
        target_id=recording.machine_id,
        target_label=recording.machine_name,
        details={"recording_id": str(recording.id)},
    )
    return {**terminal_recording.as_dict(recording), **cast}
