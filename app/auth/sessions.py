"""Server-side login sessions (see `app.db.models.user_session` for why this
isn't a stateless signed cookie), plus the short-lived signed "pending 2FA"
ticket used between "password/LDAP check passed" and "TOTP code confirmed".

Session lifetime: sliding — each validated request pushes `expires_at` out
by `SESSION_IDLE_TIMEOUT`, capped at `SESSION_ABSOLUTE_MAX` from creation, so
an abandoned-but-never-explicitly-logged-out browser tab still eventually
needs a fresh login.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.responses import Response

from app.core.config import get_settings
from app.db.models.role import Role
from app.db.models.user import User
from app.db.models.user_session import UserSession

SESSION_COOKIE_NAME = "session"
SESSION_IDLE_TIMEOUT = timedelta(hours=12)
SESSION_ABSOLUTE_MAX = timedelta(days=30)

PENDING_TOTP_COOKIE_NAME = "totp_pending"
_PENDING_TOTP_SALT = "totp-pending-2fa"
_PENDING_TOTP_MAX_AGE_SECONDS = 300


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _as_aware_utc(value: datetime) -> datetime:
    """Normalize a datetime read back from the DB to tz-aware UTC,
    regardless of whether the round-trip kept its tzinfo (Postgres, via
    asyncpg) or dropped it (SQLite in tests) — every timestamp this app
    writes is already UTC, so a naive value is assumed to already be UTC
    rather than treated as local time. Same reasoning as
    `app.audit._normalized_timestamp` / `User.is_locked_out`, but returning
    a comparable/addable datetime instead of just a comparison result,
    since `get_valid_session` below needs to do arithmetic on it too."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _is_in_future(value: datetime) -> bool:
    return _as_aware_utc(value) > datetime.now(UTC)


async def create_session(
    db: AsyncSession, user: User, *, ip_address: str | None, user_agent: str | None
) -> tuple[UserSession, str]:
    raw_token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    session = UserSession(
        user_id=user.id,
        token_hash=_hash_token(raw_token),
        expires_at=now + SESSION_IDLE_TIMEOUT,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:255] or None,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return session, raw_token


async def get_valid_session(db: AsyncSession, raw_token: str) -> UserSession | None:
    """Look up, validate, and (if still valid) slide the expiry of the
    session for `raw_token`. Eager-loads `user.role.permission_grants` since
    the caller (the auth middleware) needs those available after this
    session closes — see `User.has_permission`."""
    result = await db.execute(
        select(UserSession)
        .options(
            selectinload(UserSession.user)
            .selectinload(User.role)
            .selectinload(Role.permission_grants)
        )
        .where(UserSession.token_hash == _hash_token(raw_token))
    )
    session = result.scalar_one_or_none()
    if session is None or session.revoked_at is not None:
        return None
    absolute_cutoff = _as_aware_utc(session.created_at) + SESSION_ABSOLUTE_MAX
    if not _is_in_future(session.expires_at) or not _is_in_future(absolute_cutoff):
        return None
    if not session.user.is_active:
        return None

    now = datetime.now(UTC)
    session.expires_at = min(now + SESSION_IDLE_TIMEOUT, absolute_cutoff)
    session.last_seen_at = now
    await db.commit()
    return session


async def revoke_session(db: AsyncSession, session: UserSession) -> None:
    session.revoked_at = datetime.now(UTC)
    await db.commit()


async def revoke_all_sessions_for_user(
    db: AsyncSession, user_id: uuid.UUID, *, except_session_id: uuid.UUID | None = None
) -> None:
    """Used for "log out everywhere" and whenever an account's access needs
    to be cut immediately (deactivation, role change by another admin) — see
    `app/web/routes/users.py`."""
    stmt = (
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    if except_session_id is not None:
        stmt = stmt.where(UserSession.id != except_session_id)
    await db.execute(stmt)
    await db.commit()


def set_session_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        raw_token,
        httponly=True,
        samesite="strict",
        secure=get_settings().is_production,
        max_age=int(SESSION_IDLE_TIMEOUT.total_seconds()),
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME)


def _pending_totp_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        get_settings().secret_key.get_secret_value(), salt=_PENDING_TOTP_SALT
    )


def create_pending_totp_ticket(user_id: uuid.UUID) -> str:
    """A short-lived signed value naming which user just passed the first
    login step (password/LDAP) and still needs to confirm a TOTP code.
    Deliberately not a DB row — it's only ever needed for a few minutes and
    carries no privilege by itself (it doesn't grant a session)."""
    return _pending_totp_serializer().dumps(str(user_id))


def read_pending_totp_ticket(ticket: str) -> uuid.UUID | None:
    try:
        raw = _pending_totp_serializer().loads(ticket, max_age=_PENDING_TOTP_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


def set_pending_totp_cookie(response: Response, ticket: str) -> None:
    response.set_cookie(
        PENDING_TOTP_COOKIE_NAME,
        ticket,
        httponly=True,
        samesite="strict",
        secure=get_settings().is_production,
        max_age=_PENDING_TOTP_MAX_AGE_SECONDS,
    )


def clear_pending_totp_cookie(response: Response) -> None:
    response.delete_cookie(PENDING_TOTP_COOKIE_NAME)
