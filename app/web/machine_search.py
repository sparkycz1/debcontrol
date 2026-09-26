"""Free-text search across machines — used by Machines, "All machines", and
individual group pages, so search works the same everywhere machines are
listed."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import ColumnElement, or_, select
from sqlalchemy.sql import Select

from app.db.models.machine import Machine
from app.db.models.machine_change import MachineChange
from app.db.models.machine_tag import Tag

# The machine list's "Status" filter (`?status=`), shared with
# `GET /api/v1/machines` — see `apply_status_filter`.
STATUS_FILTERS = ("offline", "updates", "security", "reboot", "changed", "unconfirmed")
# "changed" = a configuration change detected within this many days.
CHANGED_WITHIN_DAYS = 7

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
    against name, IP, discovered hostname, OS/kernel version, username,
    notes, or a tag name. `.ilike()` is used rather than `.like()` since
    it's portable — it compiles to native `ILIKE` on Postgres and a
    `lower(...)`-based equivalent elsewhere (e.g. SQLite, used in tests).

    Tag names are matched here (loosely, substring, same as everything
    else this checks) rather than only through the dedicated exact-match
    `apply_tag_filter` below, so the plain search box alone is enough to
    find "machines tagged prod" without a separate tag picker control —
    the machine list's own UI relies on exactly this to fold tag search
    into its one search field; see partials/machine_search_form.html.
    """
    pattern = f"%{query.strip()}%"
    return or_(
        *(column.ilike(pattern) for column in _SEARCH_COLUMNS),
        Machine.tags.any(Tag.name.ilike(pattern)),
    )


def apply_tag_filter[S: Select[Machine]](query: S, tags: list[str], tag_mode: str) -> S:
    """Filter `query` by one or more tag names — `tag_mode="or"` (default,
    and used whenever `tag_mode` isn't exactly `"and"`) matches a machine
    carrying *any* of `tags`; `"and"` matches only a machine carrying
    *every one* of them. Shared by the web machine list
    (`app/web/routes/machines.py`) and its REST equivalent
    (`app/web/routes/api_v1.py`) so the two filter identically.

    `"and"` is one `.any()` clause per tag, chained as separate `.where()`
    calls rather than combined in one `and_(...)` — SQLAlchemy already ANDs
    successive `.where()` calls together, and each `.any()` needs its own
    independent correlated EXISTS subquery (the same machine must match
    each one separately; a single subquery checking for several tag names
    at once would still just be an OR across them, not AND).
    """
    names = [t.strip().lower() for t in tags if t.strip()]
    if not names:
        return query
    if tag_mode == "and":
        for name in names:
            query = query.where(Machine.tags.any(Tag.name == name))
        return query
    return query.where(Machine.tags.any(Tag.name.in_(names)))


def apply_status_filter[S: Select[Machine]](query: S, status: str) -> S:
    """Filter by one of `STATUS_FILTERS` (anything else: unchanged) —
    offline (the reachability check fails), updates (any pending apt/
    flatpak/snap update), security (pending apt security updates), reboot
    (a newer kernel is installed than running), changed (a configuration
    change detected in the last `CHANGED_WITHIN_DAYS` days — see
    `app.services.config_drift`), unconfirmed (no pinned host key yet)."""
    if status == "offline":
        return query.where(Machine.is_reachable.is_(False))
    if status == "updates":
        return query.where(
            or_(
                Machine.upgradable_count > 0,
                Machine.flatpak_upgradable_count > 0,
                Machine.snap_upgradable_count > 0,
            )
        )
    if status == "security":
        return query.where(Machine.security_upgradable_count > 0)
    if status == "reboot":
        return query.where(Machine.reboot_required.is_(True))
    if status == "changed":
        since = datetime.now(UTC) - timedelta(days=CHANGED_WITHIN_DAYS)
        return query.where(
            Machine.id.in_(
                select(MachineChange.machine_id).where(MachineChange.detected_at >= since)
            )
        )
    if status == "unconfirmed":
        return query.where(Machine.host_key_fingerprint.is_(None))
    return query


def apply_group_filter[S: Select[Machine]](query: S, group: str) -> S:
    """`group` is a machine group id, or `"none"` for machines in no group;
    anything else leaves `query` unchanged. Access scoping stays the
    caller's `machines_visible_to` query's job."""
    if group == "none":
        return query.where(Machine.group_id.is_(None))
    try:
        group_id = uuid.UUID(group)
    except (ValueError, TypeError):
        return query
    return query.where(Machine.group_id == group_id)
