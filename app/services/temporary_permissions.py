"""Grant/revoke/list time-limited per-user permissions — see
`app.db.models.temporary_permission_grant`'s module docstring for the
model. Shared between the web routes (`app/web/routes/users.py`) and the
REST API (`app/web/routes/api_v1_users.py`), same "one service function,
two doors" convention as `app.services.machine_actions`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.role import Permission
from app.db.models.temporary_permission_grant import TemporaryPermissionGrant

# A generous upper bound, not "unlimited" — a grant that's forgotten about
# should still eventually lapse on its own even if nobody remembers to
# revoke it. An admin who genuinely needs longer just grants the
# permission through the account's actual role instead.
MAX_GRANT_HOURS = 24 * 30  # 30 days


async def list_temporary_grants(
    db: AsyncSession, user_id: uuid.UUID
) -> list[TemporaryPermissionGrant]:
    """Every grant ever made for this user, newest first — active, expired,
    and revoked alike, so the page can show the full history, not just
    what's currently in effect."""
    result = await db.execute(
        select(TemporaryPermissionGrant)
        .where(TemporaryPermissionGrant.user_id == user_id)
        .order_by(TemporaryPermissionGrant.granted_at.desc())
    )
    return list(result.scalars().all())


async def grant_temporary_permission(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    permission: Permission,
    hours: int,
    granted_by_id: uuid.UUID | None,
) -> TemporaryPermissionGrant:
    """`hours` must already be validated (1..MAX_GRANT_HOURS) by the
    caller — this never clamps or rejects it, so a bug upstream fails
    loudly instead of silently granting a different duration than asked
    for."""
    now = datetime.now(UTC)
    grant = TemporaryPermissionGrant(
        user_id=user_id,
        permission=permission,
        granted_by_id=granted_by_id,
        granted_at=now,
        expires_at=now + timedelta(hours=hours),
    )
    db.add(grant)
    await db.commit()
    await db.refresh(grant)
    return grant


async def revoke_temporary_grant(
    db: AsyncSession, *, user_id: uuid.UUID, grant_id: uuid.UUID
) -> TemporaryPermissionGrant | None:
    """Ends a grant early. Returns `None` (a no-op, not an error) for an
    unknown grant, one belonging to a different user, or one already
    revoked — same "not found, not forbidden" treatment other per-account
    lookups in this app give an out-of-scope id."""
    result = await db.execute(
        select(TemporaryPermissionGrant).where(
            TemporaryPermissionGrant.id == grant_id,
            TemporaryPermissionGrant.user_id == user_id,
        )
    )
    grant = result.scalar_one_or_none()
    if grant is None or grant.revoked_at is not None:
        return None
    grant.revoked_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(grant)
    return grant
