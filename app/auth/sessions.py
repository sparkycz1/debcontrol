"""Server-side login sessions (see `app.db.models.user_session` for why this
isn't a stateless signed cookie), plus the short-lived signed "pending 2FA"
ticket used between "password/LDAP check passed" and "TOTP code confirmed".

Session lifetime: sliding — each validated request pushes `expires_at` out
by the idle timeout, capped at the absolute maximum from creation, so an
abandoned-but-never-explicitly-logged-out browser tab still eventually
needs a fresh login. Both come from Settings -> Security
(`app.auth.session_policy`).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.responses import Response

from app.auth import session_policy
from app.core.config import get_settings
from app.db.models.role import Role
from app.db.models.user import User
from app.db.models.user_session import UserSession

SESSION_COOKIE_NAME = "session"

IMPERSONATION_RETURN_COOKIE_NAME = "impersonation_return"
_IMPERSONATION_RETURN_SALT = "impersonation-return"
# Generous compared to a normal session's own idle timeout — this cookie
# only ever needs to outlive however long an admin spends poking around as
# someone else, not a whole day. Session validity itself (both the
# impersonated one and the original one it points back to) is still checked
# independently on every request/at stop time, so this is just an outer
# bound on the signed value itself, not a privilege in its own right.
_IMPERSONATION_RETURN_MAX_AGE_SECONDS = 12 * 60 * 60

PENDING_TOTP_COOKIE_NAME = "totp_pending"
_PENDING_TOTP_SALT = "totp-pending-2fa"
_PENDING_TOTP_MAX_AGE_SECONDS = 300
# Despite the name, this ticket also carries "which account passed step
# one" for a WebAuthn/passkey second factor, not just TOTP — the state it
# holds ("this account, mid-login, still needs a second factor") is
# identical either way, so app/web/routes/auth.py's WebAuthn routes reuse
# it rather than minting a second, redundant ticket type.

WEBAUTHN_CHALLENGE_COOKIE_NAME = "webauthn_challenge"
_WEBAUTHN_CHALLENGE_SALT = "webauthn-challenge"
_WEBAUTHN_CHALLENGE_MAX_AGE_SECONDS = 300


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
    policy = await session_policy.load_policy(db)
    session = UserSession(
        user_id=user.id,
        token_hash=_hash_token(raw_token),
        expires_at=now + policy.idle_timeout,
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
            .selectinload(Role.permission_grants),
            selectinload(UserSession.impersonator),
        )
        .where(UserSession.token_hash == _hash_token(raw_token))
    )
    session = result.scalar_one_or_none()
    if session is None or session.revoked_at is not None:
        return None
    policy = await session_policy.load_policy(db)
    absolute_cutoff = _as_aware_utc(session.created_at) + policy.absolute_max
    if not _is_in_future(session.expires_at) or not _is_in_future(absolute_cutoff):
        return None
    if not session.user.is_active:
        return None

    now = datetime.now(UTC)
    session.expires_at = min(now + policy.idle_timeout, absolute_cutoff)
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


async def start_impersonation(
    db: AsyncSession,
    *,
    admin: User,
    target: User,
    ip_address: str | None,
    user_agent: str | None,
) -> tuple[UserSession, str]:
    """Create a new session for `target`, tagged as started by `admin` — see
    `app.web.routes.impersonation`. The admin's own original session is left
    exactly as it is; the caller is responsible for stashing its raw token
    (in the signed `impersonation_return` cookie) before swapping the
    browser's session cookie over to this new one."""
    raw_token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    policy = await session_policy.load_policy(db)
    session = UserSession(
        user_id=target.id,
        impersonator_id=admin.id,
        token_hash=_hash_token(raw_token),
        expires_at=now + policy.idle_timeout,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:255] or None,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return session, raw_token


def _impersonation_return_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        get_settings().secret_key.get_secret_value(),
        salt=_IMPERSONATION_RETURN_SALT,
        signer_kwargs={"digest_method": hashlib.sha256},
    )


def create_impersonation_return_ticket(raw_session_token: str) -> str:
    """Signs the admin's own raw session token so it can be handed back to
    them, unreadable/untamperable by the browser in between, once they stop
    impersonating — see `stop_impersonation`."""
    return _impersonation_return_serializer().dumps(raw_session_token)


def read_impersonation_return_ticket(ticket: str) -> str | None:
    try:
        raw = _impersonation_return_serializer().loads(
            ticket, max_age=_IMPERSONATION_RETURN_MAX_AGE_SECONDS
        )
    except (BadSignature, SignatureExpired):
        return None
    return raw if isinstance(raw, str) else None


def set_impersonation_return_cookie(response: Response, ticket: str) -> None:
    response.set_cookie(
        IMPERSONATION_RETURN_COOKIE_NAME,
        ticket,
        httponly=True,
        samesite="strict",
        secure=get_settings().is_production,
        max_age=_IMPERSONATION_RETURN_MAX_AGE_SECONDS,
    )


def clear_impersonation_return_cookie(response: Response) -> None:
    response.delete_cookie(IMPERSONATION_RETURN_COOKIE_NAME)


async def stop_impersonation(
    db: AsyncSession, *, impersonation_session: UserSession, return_ticket: str
) -> tuple[UserSession, str] | None:
    """Ends one impersonation: revokes `impersonation_session` and resolves
    the original admin session (and its raw token, to put back in the
    cookie) the return ticket points back to. Returns `None` (nothing to
    restore — caller should fall back to an ordinary logout) if the ticket
    is missing/expired/tampered, or if the session it names is itself no
    longer valid (expired, already revoked elsewhere)."""
    await revoke_session(db, impersonation_session)
    raw_original_token = read_impersonation_return_ticket(return_ticket)
    if raw_original_token is None:
        return None
    restored = await get_valid_session(db, raw_original_token)
    if restored is None:
        return None
    return restored, raw_original_token


def set_session_cookie(response: Response, raw_token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        raw_token,
        httponly=True,
        samesite="strict",
        secure=get_settings().is_production,
        # The browser may keep the cookie for the session's whole possible
        # life; the idle timeout is enforced server-side on every request.
        max_age=int(session_policy.last_known_policy().absolute_max.total_seconds()),
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME)


def _pending_totp_serializer() -> URLSafeTimedSerializer:
    # digest_method=sha256, not itsdangerous's own default (HMAC-SHA1) — see
    # wiki/Architecture.md's "FIPS alignment" section. HMAC-SHA1 is itself
    # still FIPS-approved for a MAC, so this isn't fixing a real weakness,
    # just removing the one non-approved-looking default in this app's
    # otherwise SHA-2-everywhere signing.
    return URLSafeTimedSerializer(
        get_settings().secret_key.get_secret_value(),
        salt=_PENDING_TOTP_SALT,
        signer_kwargs={"digest_method": hashlib.sha256},
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


def _webauthn_challenge_serializer() -> URLSafeTimedSerializer:
    # See the digest_method comment on `_pending_totp_serializer` above.
    return URLSafeTimedSerializer(
        get_settings().secret_key.get_secret_value(),
        salt=_WEBAUTHN_CHALLENGE_SALT,
        signer_kwargs={"digest_method": hashlib.sha256},
    )


def create_webauthn_challenge_ticket(*, user_id: uuid.UUID, challenge: bytes, purpose: str) -> str:
    """A short-lived signed value carrying the challenge issued for one
    WebAuthn ceremony (`purpose` is `"register"` or `"authenticate"`)
    together with which account it's for — read back by the matching
    `.../verify` route so the challenge checked against the browser's
    response is exactly the one this server issued, and a registration
    challenge can never be replayed to complete an authentication (or vice
    versa). Deliberately not a DB row, same reasoning as the pending-TOTP
    ticket above — a ceremony only ever takes a few seconds."""
    return _webauthn_challenge_serializer().dumps(
        {
            "user_id": str(user_id),
            "challenge": base64.urlsafe_b64encode(challenge).decode("ascii"),
            "purpose": purpose,
        }
    )


def read_webauthn_challenge_ticket(ticket: str, *, purpose: str) -> tuple[uuid.UUID, bytes] | None:
    try:
        raw = _webauthn_challenge_serializer().loads(
            ticket, max_age=_WEBAUTHN_CHALLENGE_MAX_AGE_SECONDS
        )
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(raw, dict) or raw.get("purpose") != purpose:
        return None
    try:
        user_id = uuid.UUID(raw["user_id"])
        challenge = base64.urlsafe_b64decode(raw["challenge"])
    except (ValueError, KeyError, TypeError, binascii.Error):
        return None
    return user_id, challenge


def set_webauthn_challenge_cookie(response: Response, ticket: str) -> None:
    response.set_cookie(
        WEBAUTHN_CHALLENGE_COOKIE_NAME,
        ticket,
        httponly=True,
        samesite="strict",
        secure=get_settings().is_production,
        max_age=_WEBAUTHN_CHALLENGE_MAX_AGE_SECONDS,
    )


def clear_webauthn_challenge_cookie(response: Response) -> None:
    response.delete_cookie(WEBAUTHN_CHALLENGE_COOKIE_NAME)
