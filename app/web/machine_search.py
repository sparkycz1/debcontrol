"""Free-text search across machines — used by Machines, "All machines", and
individual group pages, so search works the same everywhere machines are
listed."""

from __future__ import annotations

from sqlalchemy import ColumnElement, or_

from app.db.models.machine import Machine

_SEARCH_COLUMNS = (
    Machine.name,
    Machine.ip_address,
    Machine.discovered_hostname,
    Machine.os_version,
    Machine.kernel_version,
    Machine.username,
    Machine.description,
)


def machine_search_clause(query: str) -> ColumnElement[bool]:
    """A SQLAlchemy filter matching `query` (case-insensitive, substring)
    against name, IP, discovered hostname, OS/kernel version, username, or
    notes. `.ilike()` is used rather than `.like()` since it's portable —
    it compiles to native `ILIKE` on Postgres and a `lower(...)`-based
    equivalent elsewhere (e.g. SQLite, used in tests)."""
    pattern = f"%{query.strip()}%"
    return or_(*(column.ilike(pattern) for column in _SEARCH_COLUMNS))
