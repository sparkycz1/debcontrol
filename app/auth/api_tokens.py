"""Per-user API tokens — see `app.db.models.api_token` for the model and the
overall design (why a token authorizes whatever the owning user's role
currently permits, rather than a snapshot taken at creation time).

Token format: a random value prefixed `dcpat_` (debcontrol Personal Access
Token) so a leaked one is recognizable in logs/scanners, same idea as
GitHub/Stripe-style prefixed tokens. Only its SHA-256 hash is ever stored —
same scheme as `app.auth.sessions`'s session tokens.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.api_token import ApiToken
from app.db.models.role import Role
from app.db.models.user import User

_TOKEN_PREFIX = "dcpat_"  # noqa: S105 - a public format prefix, not a secret value
_PREFIX_DISPLAY_LENGTH = 12  # "dcpat_" + 6 chars of the random part.


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


async def create_api_token(
    db: AsyncSession,
    user: User,
    *,
    name: str,
    expires_at: datetime | None,
    read_only: bool = False,
    machine_group_ids: list[uuid.UUID] | None = None,
) -> tuple[ApiToken, str]:
    raw_token = _TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = ApiToken(
        user_id=user.id,
        name=name,
        token_hash=_hash_token(raw_token),
        token_prefix=raw_token[:_PREFIX_DISPLAY_LENGTH],
        expires_at=expires_at,
        read_only=read_only,
        machine_group_ids=(
            [str(group_id) for group_id in machine_group_ids]
            if machine_group_ids is not None
            else None
        ),
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return token, raw_token


async def get_user_for_api_token(db: AsyncSession, raw_token: str) -> User | None:
    """The user behind a bearer token — see `get_valid_api_token`. For a
    caller that only needs "who is this"; one that must honor the token's
    own limits (`read_only`, `machine_group_ids`) needs the token itself."""
    token = await get_valid_api_token(db, raw_token)
    return token.user if token is not None else None


async def get_valid_api_token(db: AsyncSession, raw_token: str) -> ApiToken | None:
    """Look up a bearer token with its (still active) user loaded, or None
    if the token is unknown, revoked, expired, or its owner is deactivated.
    Also opportunistically records `last_used_at` — best-effort, a failure
    here shouldn't block the request that's using the token, so callers
    should treat this as a read even though it writes.
    """
    result = await db.execute(
        select(ApiToken)
        .options(
            selectinload(ApiToken.user).selectinload(User.role).selectinload(Role.permission_grants)
        )
        .where(ApiToken.token_hash == _hash_token(raw_token))
    )
    token = result.scalar_one_or_none()
    if token is None or token.revoked_at is not None:
        return None
    if token.expires_at is not None:
        expires_at = token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= datetime.now(UTC):
            return None
    if not token.user.is_active:
        return None
    if not token.user.api_access_enabled:
        return None

    token.last_used_at = datetime.now(UTC)
    await db.commit()
    return token


async def revoke_api_token(db: AsyncSession, token_id: uuid.UUID, *, owner_id: uuid.UUID) -> bool:
    """Revoke a token, but only if it belongs to `owner_id` — self-service,
    like everything else under "My account". Returns whether a token was
    actually revoked."""
    token = await db.get(ApiToken, token_id)
    if token is None or token.user_id != owner_id or token.revoked_at is not None:
        return False
    token.revoked_at = datetime.now(UTC)
    await db.commit()
    return True
