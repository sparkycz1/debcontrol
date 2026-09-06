"""REST API for the audit log — mirrors `app/web/routes/audit.py` (list/
filter, CSV/JSON export)."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import require_api_permission
from app.db.models.audit_log import AuditLogEntry
from app.db.models.role import Permission
from app.db.session import get_db
from app.web.audit_search import apply_audit_filters
from app.web.routes.audit import _EXPORT_FIELDS, _csv_safe, _entry_to_export_row

router = APIRouter(prefix="/api/v1/audit")

_view = Depends(require_api_permission(Permission.AUDIT_VIEW))

_PAGE_SIZE = 50


def _entry_to_dict(entry: AuditLogEntry) -> dict[str, Any]:
    return {
        "id": str(entry.id),
        "sequence": entry.sequence,
        "created_at": entry.created_at.isoformat(),
        "actor": entry.actor,
        "ip_address": entry.ip_address,
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
    format: str = "csv",  # noqa: A002
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
