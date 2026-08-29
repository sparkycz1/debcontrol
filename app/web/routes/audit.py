"""Audit log — a read-only view over `AuditLogEntry` (see `app.audit` for
how entries get written), plus a CSV/JSON export for archival/compliance
outside the app and, for a SIEM, live syslog forwarding (see
`app.audit_syslog`, configured on the Settings page)."""

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
from app.auth.dependencies import require_permission
from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.models.role import Permission
from app.db.session import get_db
from app.web.audit_search import audit_search_clause
from app.web.templating import templates

router = APIRouter(
    prefix="/audit", dependencies=[Depends(require_permission(Permission.AUDIT_VIEW))]
)

_PAGE_SIZE = 50

_EXPORT_FIELDS = (
    "sequence",
    "created_at",
    "actor",
    "ip_address",
    "action",
    "outcome",
    "summary",
    "target_type",
    "target_id",
    "target_label",
    "details",
    "prev_hash",
    "entry_hash",
)


# Spreadsheet apps (Excel, LibreOffice, Google Sheets) treat a cell starting
# with one of these characters as a formula, not text — a machine/group/role
# name or a username (all attacker-influenceable, end up in `summary`/
# `target_label`/`details`) crafted like `=cmd|'/c calc'!A0` would otherwise
# execute when an admin opens the exported CSV. Prefixing with a single quote
# forces spreadsheet apps to treat it as plain text while leaving the actual
# audit data (and the JSON export, never opened by a spreadsheet app) intact.
_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(_FORMULA_TRIGGER_CHARS):
        return f"'{value}"
    return value


def _entry_to_export_row(entry: AuditLogEntry) -> dict[str, Any]:
    return {
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
        "details": json.dumps(entry.details) if entry.details is not None else None,
        "prev_hash": entry.prev_hash,
        "entry_hash": entry.entry_hash,
    }


@router.get("")
async def list_audit_log(
    request: Request,
    db: AsyncSession = Depends(get_db),
    q: str = "",
    outcome: str = "",
    page: int = 1,
) -> Response:
    page = max(page, 1)
    query = select(AuditLogEntry)
    if q.strip():
        query = query.where(audit_search_clause(q))
    if outcome in {o.value for o in AuditOutcome}:
        query = query.where(AuditLogEntry.outcome == AuditOutcome(outcome))

    # Fetch one extra row to know whether an "Older" page exists, without a
    # separate COUNT(*) query — this table is append-only and can grow large.
    offset = (page - 1) * _PAGE_SIZE
    result = await db.execute(
        query.order_by(AuditLogEntry.created_at.desc()).offset(offset).limit(_PAGE_SIZE + 1)
    )
    entries = list(result.scalars().all())
    has_older = len(entries) > _PAGE_SIZE
    entries = entries[:_PAGE_SIZE]

    return templates.TemplateResponse(
        request,
        "audit/list.html",
        {
            "entries": entries,
            "outcomes": list(AuditOutcome),
            "q": q,
            "outcome": outcome,
            "page": page,
            "has_older": has_older,
        },
    )


@router.get("/export")
async def export_audit_log(
    request: Request,
    db: AsyncSession = Depends(get_db),
    q: str = "",
    outcome: str = "",
    format: str = "csv",  # noqa: A002 - matches the query param name, not shadowing anything here
) -> Response:
    """Export the audit log — respecting the same `q`/`outcome` filters as
    the list view — as CSV or JSON, for archival/compliance outside the app.
    A plain `<a href>` download link (see `audit/list.html`), not a POST:
    the only side effect is an audit entry for the export itself, not
    anything worth CSRF-protecting. Not paginated — fetches every matching
    row in one go, which is fine for an infrequent, admin-triggered action
    on a self-hosted tool's own table, but could be slow on a very large,
    unfiltered log.
    """
    query = select(AuditLogEntry)
    if q.strip():
        query = query.where(audit_search_clause(q))
    if outcome in {o.value for o in AuditOutcome}:
        query = query.where(AuditLogEntry.outcome == AuditOutcome(outcome))
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
