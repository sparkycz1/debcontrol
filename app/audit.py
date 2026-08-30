"""Audit logging — the single write path for `AuditLogEntry`, and hash-chain
verification.

Every route or background job that mutates something, or that refuses to
because a safeguard tripped (a typed confirmation that didn't match, a
missing pinned host key, a bad self-registration token, a failed login),
calls `log_event` right after. `actor` is filled in automatically from the
logged-in user on the request (see `log_event`'s docstring) — routes don't
need to pass it themselves; a background job (the scheduler, the retention
purge) passes a fixed label instead, since it has no request/user at all.

Every entry is hash-chained: `entry_hash` covers this entry's own fields
plus the previous entry's `entry_hash`, so altering or deleting an entry
breaks the chain from that point on — `verify_chain` below detects that.
Writers (possibly in different processes — the web app and every Celery
worker child both log events) serialize through `AuditChainState`, a one-row table
locked with `SELECT ... FOR UPDATE` for the duration of one entry's write,
so two concurrent entries can never both link to the same previous hash.

`log_event` commits independently of whatever the caller is doing — call it
*after* the caller's own commit (if any), never before, so a failed audit
write can never roll back the action it's describing, and a validation
failure that made nothing else worth committing still gets its own record.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.audit_log import (
    CHAIN_STATE_SINGLETON_ID,
    AuditChainState,
    AuditLogEntry,
    AuditOutcome,
)

logger = logging.getLogger(__name__)


def client_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    return request.client.host


def _normalized_timestamp(value: datetime) -> str:
    """A stable string for `value` regardless of whether the DB round-trip
    kept its tzinfo (Postgres, via asyncpg) or dropped it (SQLite in
    tests) — every `created_at` this app writes is already UTC, so a naive
    value is assumed to already be UTC rather than treated as local time."""
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value.isoformat()


def _canonical_payload(
    *,
    entry_id: uuid.UUID,
    sequence: int,
    created_at: datetime,
    actor: str | None,
    ip_address: str | None,
    action: str,
    outcome: AuditOutcome,
    target_type: str | None,
    target_id: str | None,
    target_label: str | None,
    summary: str,
    details: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "id": str(entry_id),
        "sequence": sequence,
        "created_at": _normalized_timestamp(created_at),
        "actor": actor,
        "ip_address": ip_address,
        "action": action,
        "outcome": outcome.value,
        "target_type": target_type,
        "target_id": target_id,
        "target_label": target_label,
        "summary": summary,
        "details": details,
    }


def _compute_entry_hash(prev_hash: str | None, payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    material = f"{prev_hash or ''}\n{canonical}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


async def _get_locked_chain_state(db: AsyncSession) -> AuditChainState:
    """Fetch (creating on first use) the singleton chain-tip row, locked
    for the rest of this transaction — see the module docstring."""
    result = await db.execute(
        select(AuditChainState)
        .where(AuditChainState.id == CHAIN_STATE_SINGLETON_ID)
        .with_for_update()
    )
    state = result.scalar_one_or_none()
    if state is not None:
        return state

    state = AuditChainState(id=CHAIN_STATE_SINGLETON_ID, last_hash=None, entry_count=0)
    db.add(state)
    try:
        await db.flush()
    except IntegrityError:
        # Another writer created the singleton row concurrently — only
        # possible for the very first audit entry ever recorded. Their
        # commit already happened by the time ours fails, so a locked
        # re-read now finds their row.
        await db.rollback()
        result = await db.execute(
            select(AuditChainState)
            .where(AuditChainState.id == CHAIN_STATE_SINGLETON_ID)
            .with_for_update()
        )
        state = result.scalar_one()
    return state


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
    """Record one audit entry, chained to the previous one.

    `ip_address` is taken from `request` when given; pass `ip_address=`
    directly for background jobs (a scheduled task firing on its own) that
    have no request to read one from — those are recorded with `actor` set
    to a fixed label like "scheduler (automatic)" instead.

    `actor` is likewise taken from `request.state.user` (set by
    `app.auth.middleware` for every authenticated request) when `request`
    is given and `actor` wasn't passed explicitly — which is every existing
    call site with a `request`, so no route had to be touched individually
    to start recording *who* did something once logins existed. Pass
    `actor=` explicitly only for the pre-login exception (a failed login
    attempt itself has no session to read a user from) or a background
    job's fixed label.
    """
    resolved_ip = client_ip(request) if request is not None else ip_address
    if actor is None and request is not None:
        request_user = getattr(request.state, "user", None)
        if request_user is not None:
            actor = request_user.username
    target_id_str = str(target_id) if target_id is not None else None
    entry_id = uuid.uuid4()
    created_at = datetime.now(UTC)

    try:
        state = await _get_locked_chain_state(db)
        sequence = state.entry_count + 1
        payload = _canonical_payload(
            entry_id=entry_id,
            sequence=sequence,
            created_at=created_at,
            actor=actor,
            ip_address=resolved_ip,
            action=action,
            outcome=outcome,
            target_type=target_type,
            target_id=target_id_str,
            target_label=target_label,
            summary=summary,
            details=details,
        )
        entry_hash = _compute_entry_hash(state.last_hash, payload)

        entry = AuditLogEntry(
            id=entry_id,
            created_at=created_at,
            actor=actor,
            ip_address=resolved_ip,
            action=action,
            outcome=outcome,
            target_type=target_type,
            target_id=target_id_str,
            target_label=target_label,
            summary=summary,
            details=details,
            sequence=sequence,
            prev_hash=state.last_hash,
            entry_hash=entry_hash,
        )
        state.last_hash = entry_hash
        state.entry_count = sequence
        db.add(entry)
        await db.commit()

        # Best-effort live mirror to an external syslog server/SIEM, if
        # configured — see app.audit_syslog's module docstring for why a
        # delivery failure here is only ever logged, never raised.
        from app.audit_syslog import forward_to_syslog  # local: avoid an import cycle
        from app.core.app_settings import get_or_create_app_settings

        try:
            app_settings = await get_or_create_app_settings(db)
            await forward_to_syslog(app_settings, entry)
        except Exception:
            logger.warning("Failed to forward audit entry to syslog", exc_info=True)
    except Exception:
        # An audit trail gap is far better than a broken feature — never let
        # a failure to log take down the action it's describing.
        logger.exception("Failed to record audit log entry for action=%s", action)
        await db.rollback()


@dataclass(frozen=True)
class ChainVerificationResult:
    ok: bool
    checked: int
    broken_at_sequence: int | None
    message: str


async def verify_chain(db: AsyncSession) -> ChainVerificationResult:
    """Recompute every chained entry's hash from its own fields and its
    link to the previous entry, and confirm the chain's recorded tip
    matches the newest entry — catches both an altered entry (content
    changed, hash doesn't match) and deleted entries (a gap in the
    sequence, or a tip that no longer matches the newest surviving entry).

    Entries written before hash chaining existed (`sequence IS NULL`) are
    skipped, not treated as a break — there's nothing to verify them
    against.
    """
    result = await db.execute(
        select(AuditLogEntry)
        .where(AuditLogEntry.sequence.is_not(None))
        .order_by(AuditLogEntry.sequence)
    )
    entries = list(result.scalars().all())
    if not entries:
        return ChainVerificationResult(
            ok=True, checked=0, broken_at_sequence=None, message="No hash-chained entries yet."
        )

    expected_prev: str | None = None
    # The query above filters to `sequence IS NOT NULL`, so this is never
    # actually None — mypy just can't see that through the SQL filter.
    assert entries[0].sequence is not None
    expected_sequence: int = entries[0].sequence
    for entry in entries:
        if entry.sequence != expected_sequence:
            return ChainVerificationResult(
                ok=False,
                checked=len(entries),
                broken_at_sequence=expected_sequence,
                message=f"Entry #{expected_sequence} is missing — the sequence has a gap.",
            )
        if entry.prev_hash != expected_prev:
            return ChainVerificationResult(
                ok=False,
                checked=len(entries),
                broken_at_sequence=entry.sequence,
                message=(
                    f"Entry #{entry.sequence} doesn't link to the previous entry's hash — "
                    "an entry may have been removed."
                ),
            )
        payload = _canonical_payload(
            entry_id=entry.id,
            sequence=entry.sequence,
            created_at=entry.created_at,
            actor=entry.actor,
            ip_address=entry.ip_address,
            action=entry.action,
            outcome=entry.outcome,
            target_type=entry.target_type,
            target_id=entry.target_id,
            target_label=entry.target_label,
            summary=entry.summary,
            details=entry.details,
        )
        recomputed = _compute_entry_hash(expected_prev, payload)
        if recomputed != entry.entry_hash:
            return ChainVerificationResult(
                ok=False,
                checked=len(entries),
                broken_at_sequence=entry.sequence,
                message=f"Entry #{entry.sequence}'s content doesn't match its recorded hash.",
            )
        expected_prev = entry.entry_hash
        expected_sequence += 1

    state = await db.get(AuditChainState, CHAIN_STATE_SINGLETON_ID)
    if state is not None and state.last_hash != expected_prev:
        return ChainVerificationResult(
            ok=False,
            checked=len(entries),
            broken_at_sequence=None,
            message=(
                "The chain's recorded tip doesn't match the newest entry — "
                "the most recent entries may have been deleted."
            ),
        )

    return ChainVerificationResult(
        ok=True,
        checked=len(entries),
        broken_at_sequence=None,
        message=f"All {len(entries)} hash-chained entries verified intact.",
    )
