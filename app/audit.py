"""Audit logging — the single write path for `AuditLogEntry`.

Every route or background job that mutates something, or that refuses to
because a safeguard tripped (a typed confirmation that didn't match, a
missing pinned host key, a bad self-registration token), calls `log_event`
right after. There's no login yet (see the Architecture wiki page), so
there's no real "who" to record — `ip_address` is what stands in for that
today; `actor` exists and is always `None` until authentication lands.

`log_event` commits independently of whatever the caller is doing — call it
*after* the caller's own commit (if any), never before, so a failed audit
write can never roll back the action it's describing, and a validation
failure that made nothing else worth committing still gets its own record.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.audit_log import AuditLogEntry, AuditOutcome

logger = logging.getLogger(__name__)


def client_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    return request.client.host


async def log_event(
    db: AsyncSession,
    *,
    action: str,
    summary: str,
    request: Request | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    target_type: str | None = None,
    target_id: object | None = None,
    target_label: str | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
    actor: str | None = None,
) -> None:
    """Record one audit entry.

    `ip_address` is taken from `request` when given; pass `ip_address=`
    directly for background jobs (a scheduled task firing on its own) that
    have no request to read one from — those are recorded with `actor` set
    to a fixed label like "scheduler" instead.
    """
    resolved_ip = client_ip(request) if request is not None else ip_address
    entry = AuditLogEntry(
        actor=actor,
        ip_address=resolved_ip,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        target_label=target_label,
        summary=summary,
        details=details,
    )
    try:
        db.add(entry)
        await db.commit()
    except Exception:
        # An audit trail gap is far better than a broken feature — never let
        # a failure to log take down the action it's describing.
        logger.exception("Failed to record audit log entry for action=%s", action)
        await db.rollback()
