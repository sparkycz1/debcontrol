"""Audit log — a read-only view over `AuditLogEntry` (see `app.audit` for
how entries get written)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.session import get_db
from app.web.audit_search import audit_search_clause
from app.web.templating import templates

router = APIRouter(prefix="/audit")

_PAGE_SIZE = 50


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
