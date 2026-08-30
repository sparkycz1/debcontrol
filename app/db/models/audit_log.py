"""Audit trail: a durable, hash-chained record of what happened, from what
IP, and when — see `app.audit` for the single write path (`log_event`),
the chaining/locking scheme, and chain verification; `app/web/routes/
audit.py` for the **Audit** page; and `AppSettings.audit_log_retention_days`
(`app/db/models/app_settings.py`) for the retention policy, configured on
the **Settings** page.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.pg_enum import pg_enum

# Fixed id for the single AuditChainState row.
CHAIN_STATE_SINGLETON_ID = 1


class AuditOutcome(enum.StrEnum):
    SUCCESS = "success"
    # Blocked by a safeguard the app itself enforces — a typed confirmation
    # that didn't match, an unpinned host key, an invalid bearer token —
    # as opposed to a plain input mistake (FAILURE).
    DENIED = "denied"
    FAILURE = "failure"


class AuditLogEntry(Base):
    """One row per audited event. Written once and never updated — see
    `app.audit.log_event`, the only place that creates these.

    `actor` holds the logged-in username responsible for the action, filled
    in automatically by `app.audit.log_event` from `request.state.user` (see
    `app.auth.middleware`) — still nullable, since a background job with no
    request (a scheduled task firing on its own) sets a fixed actor label
    instead (see `app.scheduling.jobs._SCHEDULER_ACTOR`), and a handful of
    entries predate logins existing at all. `ip_address` is the request's
    source IP either way.

    `target_id`/`target_type` are plain strings, not foreign keys: the
    machine/group/schedule an entry refers to can later be renamed or
    deleted, and the audit trail must survive that unchanged. `target_label`
    is a snapshot of its human-readable name taken at the time of the
    event, for exactly the same reason.

    `created_at` is assigned in Python (`datetime.now(UTC)`), not via a DB
    `server_default` like most other timestamps in this app — `app.audit.
    log_event` needs the exact value *before* the row is inserted, since
    it's part of what `entry_hash` covers; a server-assigned default
    wouldn't be known until after the write.

    `sequence`/`prev_hash`/`entry_hash` form the hash chain: `entry_hash` is
    a SHA-256 over this entry's own fields plus the previous entry's
    `entry_hash`, so altering or removing an entry breaks the chain from
    that point on in a way `app.audit.verify_chain` can detect. All three
    are nullable only because a handful of entries were written before this
    chaining existed (there's no going back to hash entries that already
    happened) — every entry written by the current `log_event` always
    populates them.
    """

    __tablename__ = "audit_log_entries"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC), nullable=False, index=True
    )

    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Short machine-readable code, e.g. "machine.power.reboot",
    # "scheduled_task.create" — see app.audit for the values in use.
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    outcome: Mapped[AuditOutcome] = mapped_column(
        pg_enum(AuditOutcome, name="audit_outcome"),
        nullable=False,
        default=AuditOutcome.SUCCESS,
    )

    target_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_label: Mapped[str | None] = mapped_column(String(255), nullable=True)

    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    # Optional structured extras, e.g. {"strategy": "dist_upgrade"} or
    # {"skipped": 2} — not relied on for the list page, only shown as-is.
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # --- Hash chain (see app.audit) ---
    # 1-based position in the chain, in write order — a plain counter, not
    # derived from `created_at` (clocks aren't strictly monotonic, entry
    # order needs to be).
    sequence: Mapped[int | None] = mapped_column(Integer, nullable=True, unique=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"AuditLogEntry(id={self.id!r}, action={self.action!r}, "
            f"outcome={self.outcome!r})"
        )


class AuditChainState(Base):
    """Singleton (one row, fixed id) tracking the tip of the audit hash
    chain — `app.audit.log_event` reads and updates it under a row lock
    (`SELECT ... FOR UPDATE`) so concurrent writers from different requests
    *and* different processes (the web app and the arq worker both write
    audit entries) can never both link a new entry to the same previous
    one. Kept as its own tiny table rather than "the last row of
    `audit_log_entries`" so the lock is one specific row, not a
    query-dependent one — and so it still has a stable answer immediately
    after the retention policy purges old entries (see `AppSettings.
    audit_log_retention_days`), which only ever removes the *oldest* rows
    and never touches this state.
    """

    __tablename__ = "audit_chain_state"

    id: Mapped[int] = mapped_column(primary_key=True)
    last_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AuditChainState(entry_count={self.entry_count!r})"
