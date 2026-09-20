"""Audit log — a read-only view over `AuditLogEntry` (see `app.audit` for
how entries get written), plus a CSV/JSON export for archival/compliance
outside the app and, for a SIEM, live syslog forwarding (see
`app.audit_syslog`, configured on the Settings page)."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services.saved_audit_views import (
    DuplicateViewNameError,
    build_query_string,
    create_saved_view,
    delete_saved_view,
    list_saved_views,
)
from app.web.audit_search import apply_audit_filters
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
    "geo_country",
    "geo_city",
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
        "geo_country": entry.geo_country,
        "geo_city": entry.geo_city,
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
    current_user: User = Depends(get_current_user),
    q: str = "",
    outcome: str = "",
    target_type: str = "",
    target_id: str = "",
    page: int = 1,
) -> Response:
    page = max(page, 1)
    query = apply_audit_filters(
        select(AuditLogEntry), q=q, outcome=outcome, target_type=target_type, target_id=target_id
    )

    # Fetch one extra row to know whether an "Older" page exists, without a
    # separate COUNT(*) query — this table is append-only and can grow large.
    offset = (page - 1) * _PAGE_SIZE
    result = await db.execute(
        query.order_by(AuditLogEntry.created_at.desc()).offset(offset).limit(_PAGE_SIZE + 1)
    )
    entries = list(result.scalars().all())
    has_older = len(entries) > _PAGE_SIZE
    entries = entries[:_PAGE_SIZE]

    # For the "Showing audit history for <label>" banner — the *current*
    # label if there's still an entry to read it from (a renamed/deleted
    # target just doesn't get the banner, no worse than before this existed).
    target_label = entries[0].target_label if entries and target_type and target_id else None

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "audit/list.html",
        {
            "entries": entries,
            "outcomes": list(AuditOutcome),
            "q": q,
            "outcome": outcome,
            "target_type": target_type,
            "target_id": target_id,
            "target_label": target_label,
            "page": page,
            "has_older": has_older,
            "saved_views": await list_saved_views(db, current_user.id),
            "csrf_token": csrf_token,
            "view_error": request.query_params.get("view_error"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/saved-views", dependencies=[Depends(verify_csrf)])
async def save_audit_view(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(...),
    q: str = Form(""),
    outcome: str = Form(""),
    target_type: str = Form(""),
    target_id: str = Form(""),
) -> Response:
    """"Save this view" on the audit log — captures only the known filter
    fields (never an arbitrary querystring, see
    `app.services.saved_audit_views`), so a saved view always replays as
    exactly the same filtered `GET /audit` request."""
    query_string = build_query_string(
        {"q": q, "outcome": outcome, "target_type": target_type, "target_id": target_id}
    )
    if not name.strip():
        return RedirectResponse(url=f"/audit?{query_string}", status_code=status.HTTP_303_SEE_OTHER)
    try:
        await create_saved_view(db, current_user.id, name, query_string)
    except DuplicateViewNameError:
        return RedirectResponse(
            url=f"/audit?{query_string}&view_error=duplicate_name",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url=f"/audit?{query_string}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/saved-views/{view_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_audit_view(
    view_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    await delete_saved_view(db, current_user.id, view_id)
    return RedirectResponse(url="/audit", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/export")
async def export_audit_log(
    request: Request,
    db: AsyncSession = Depends(get_db),
    q: str = "",
    outcome: str = "",
    target_type: str = "",
    target_id: str = "",
    format: str = "csv",
) -> Response:
    """Export the audit log — respecting the same filters as the list view —
    as CSV or JSON, for archival/compliance outside the app. A plain
    `<a href>` download link (see `audit/list.html`), not a POST: the only
    side effect is an audit entry for the export itself, not anything worth
    CSRF-protecting. Not paginated — fetches every matching row in one go,
    which is fine for an infrequent, admin-triggered action on a self-hosted
    tool's own table, but could be slow on a very large, unfiltered log.
    """
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
