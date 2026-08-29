"""Free-text search across audit log entries — same `.ilike()` pattern as
`app.web.machine_search`, for the same portability reason (native `ILIKE` on
Postgres, a `lower(...)`-based equivalent on SQLite in tests)."""

from __future__ import annotations

from sqlalchemy import ColumnElement, or_

from app.db.models.audit_log import AuditLogEntry

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
