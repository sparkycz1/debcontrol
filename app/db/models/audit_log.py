"""Audit trail: a durable record of what happened, from what IP, and when —
see `app.audit` for the single write path (`log_event`) and
`app/web/routes/audit.py` for the **Audit** page.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Enum, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


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

    `actor` is nullable and, for now, always NULL: there's no login yet
    (see the Architecture wiki page's "Deliberately deferred" section), so
    there's no real identity to record. The column exists now so that once
    authentication lands, entries can start carrying a real actor without
    another migration — `ip_address` is what stands in for "who" today.

    `target_id`/`target_type` are plain strings, not foreign keys: the
    machine/group/schedule an entry refers to can later be renamed or
    deleted, and the audit trail must survive that unchanged. `target_label`
    is a snapshot of its human-readable name taken at the time of the
    event, for exactly the same reason.
    """

    __tablename__ = "audit_log_entries"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False, index=True
    )

    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Short machine-readable code, e.g. "machine.power.reboot",
    # "scheduled_task.create" — see app.audit for the values in use.
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    outcome: Mapped[AuditOutcome] = mapped_column(
        Enum(AuditOutcome, name="audit_outcome", native_enum=True),
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

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"AuditLogEntry(id={self.id!r}, action={self.action!r}, "
            f"outcome={self.outcome!r})"
        )
