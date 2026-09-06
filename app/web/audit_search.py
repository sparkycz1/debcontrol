"""Free-text search across audit log entries — same `.ilike()` pattern as
`app.web.machine_search`, for the same portability reason (native `ILIKE` on
Postgres, a `lower(...)`-based equivalent on SQLite in tests)."""

from __future__ import annotations

from sqlalchemy import ColumnElement, or_
from sqlalchemy.sql import Select

from app.db.models.audit_log import AuditLogEntry, AuditOutcome

_SEARCH_COLUMNS = (
    AuditLogEntry.action,
    AuditLogEntry.summary,
    AuditLogEntry.actor,
    AuditLogEntry.ip_address,
    AuditLogEntry.target_type,
    AuditLogEntry.target_label,
)


def audit_search_clause(query: str) -> ColumnElement[bool]:
    pattern = f"%{query.strip()}%"
    return or_(*(column.ilike(pattern) for column in _SEARCH_COLUMNS))


def apply_audit_filters[S: Select[tuple[AuditLogEntry]]](
    query: S, *, q: str, outcome: str, target_type: str, target_id: str
) -> S:
    """The four filters `app/web/routes/audit.py` and
    `app/web/routes/api_v1_audit.py` both apply identically, to both their
    list and export endpoints — kept in one place so the two never drift.

    `target_type`/`target_id` is an *exact* match — a link from a specific
    machine's/group's/user's own page ("view audit history for this") — as
    opposed to `q`'s free-text match on `target_label`, a point-in-time
    snapshot that can miss a since-renamed target.
    """
    if q.strip():
        query = query.where(audit_search_clause(q))
    if outcome in {o.value for o in AuditOutcome}:
        query = query.where(AuditLogEntry.outcome == AuditOutcome(outcome))
    if target_type.strip() and target_id.strip():
        query = query.where(
            AuditLogEntry.target_type == target_type.strip(),
            AuditLogEntry.target_id == target_id.strip(),
        )
    return query
