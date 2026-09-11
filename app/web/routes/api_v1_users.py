"""REST API for user accounts — mirrors `app/web/routes/users.py`, including
the exact same self-protection / last-admin guardrails (reused directly from
`app.auth.login`, not reimplemented).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_api_permission
from app.auth.login import count_active_users_with_permission
from app.auth.security import hash_password
from app.auth.sessions import revoke_all_sessions_for_user
from app.db.models.role import Permission, Role
from app.db.models.temporary_permission_grant import TemporaryPermissionGrant
from app.db.models.user import AuthProvider, User, role_has_permission
from app.db.session import get_db
from app.schemas.user import MIN_PASSWORD_LENGTH, UserCreate, UserUpdate
from app.services.temporary_permissions import (
    MAX_GRANT_HOURS,
    grant_temporary_permission,
    list_temporary_grants,
    revoke_temporary_grant,
)

router = APIRouter(prefix="/api/v1/users")

_manage = Depends(require_api_permission(Permission.USER_MANAGE))


def _user_to_dict(user: User) -> dict[str, object]:
    return {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "auth_provider": user.auth_provider.value,
        "role_id": str(user.role_id),
        "role_name": user.role.name if user.role else None,
        "is_active": user.is_active,
        "api_access_enabled": user.api_access_enabled,
        "totp_enabled": user.totp_enabled,
        "must_change_password": user.must_change_password,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


async def _get_user_or_404(user_id: uuid.UUID, db: AsyncSession) -> User:
    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user


async def _would_remove_last_admin(db: AsyncSession, target: User) -> bool:
    if not target.has_permission(Permission.USER_MANAGE):
        return False
    remaining = await count_active_users_with_permission(
        db, Permission.USER_MANAGE, excluding_user_id=target.id
    )
    return remaining == 0


@router.get("", dependencies=[_manage])
async def list_users_api(db: AsyncSession = Depends(get_db)) -> list[dict[str, object]]:
    result = await db.execute(select(User).options(selectinload(User.role)).order_by(User.username))
    return [_user_to_dict(u) for u in result.scalars().all()]


@router.get("/{user_id}", dependencies=[_manage])
async def get_user_api(user_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    return _user_to_dict(await _get_user_or_404(user_id, db))


@router.post("", dependencies=[_manage], status_code=status.HTTP_201_CREATED)
async def create_user_api(
    request: Request, payload: UserCreate, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    role = await db.get(Role, payload.role_id)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Selected role does not exist.",
        )
    user = User(
        username=payload.username,
        display_name=payload.display_name,
        email=payload.email,
        auth_provider=payload.auth_provider,
        password_hash=hash_password(payload.password) if payload.password else None,
        must_change_password=payload.auth_provider == AuthProvider.LOCAL,
        role_id=payload.role_id,
        api_access_enabled=payload.api_access_enabled,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f'A user named "{payload.username}" already exists, '
                "or that email is already in use by another account."
            ),
        ) from None
    user = await _get_user_or_404(user.id, db)
    await log_event(
        db,
        request=request,
        action="user.create",
        summary=f'Created user "{user.username}" ({user.auth_provider.value}, role "{role.name}")',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return _user_to_dict(user)


@router.put("/{user_id}", dependencies=[_manage])
async def update_user_api(
    request: Request,
    user_id: uuid.UUID,
    payload: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_api_permission(Permission.USER_MANAGE)),
) -> dict[str, object]:
    user = await _get_user_or_404(user_id, db)
    role = await db.get(Role, payload.role_id)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Selected role does not exist.",
        )

    if user.id == current_user.id:
        if payload.role_id != user.role_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can't change your own role — ask another administrator.",
            )
        if not payload.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can't deactivate your own account.",
            )

    becoming_local = payload.auth_provider == AuthProvider.LOCAL
    losing_local = user.auth_provider == AuthProvider.LOCAL and not becoming_local
    if becoming_local and user.auth_provider != AuthProvider.LOCAL and not payload.password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'Switching "{user.username}" to a local account needs a password.',
        )

    still_has_user_manage = payload.is_active and role_has_permission(role, Permission.USER_MANAGE)
    if user.has_permission(Permission.USER_MANAGE) and not still_has_user_manage:
        remaining = await count_active_users_with_permission(
            db, Permission.USER_MANAGE, excluding_user_id=user.id
        )
        if remaining == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "This is the last account that can manage users — "
                    "it can't lose that access."
                ),
            )

    user.username = payload.username
    user.display_name = payload.display_name
    user.email = payload.email
    user.auth_provider = payload.auth_provider
    user.role_id = payload.role_id
    user.is_active = payload.is_active
    user.api_access_enabled = payload.api_access_enabled
    if becoming_local:
        if payload.password:
            user.password_hash = hash_password(payload.password)
            user.must_change_password = True
    if losing_local:
        user.password_hash = None
        user.must_change_password = False

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f'A user named "{payload.username}" already exists, '
                "or that email is already in use by another account."
            ),
        ) from None

    if not payload.is_active:
        await revoke_all_sessions_for_user(db, user.id)

    user = await _get_user_or_404(user.id, db)
    await log_event(
        db,
        request=request,
        action="user.update",
        summary=f'Updated user "{user.username}"',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return _user_to_dict(user)


# --- Bulk actions (ad-hoc selection from the user list) --------------------
#
# Mirrors `app/web/routes/users.py`'s "Bulk actions" section, including why
# none of these need their own "last admin" guard: `_manage` already
# requires the caller to hold `user.manage`, and that account's own id is
# always dropped from the batch (see `_bulk_user_ids`), so at least one
# active `user.manage` holder is always left standing.


class _BulkUserIds(BaseModel):
    user_ids: list[uuid.UUID] = Field(min_length=1)


class _BulkSetRole(_BulkUserIds):
    role_id: uuid.UUID


def _bulk_user_ids(payload: _BulkUserIds, actor: User) -> list[uuid.UUID]:
    return [uid for uid in payload.user_ids if uid != actor.id]


async def _get_users_by_ids_api(db: AsyncSession, user_ids: list[uuid.UUID]) -> list[User]:
    if not user_ids:
        return []
    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.id.in_(user_ids))
    )
    return list(result.scalars().all())


@router.post("/bulk/deactivate", dependencies=[_manage])
async def bulk_deactivate_users_api(
    request: Request,
    payload: _BulkUserIds,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_api_permission(Permission.USER_MANAGE)),
) -> dict[str, object]:
    ids = _bulk_user_ids(payload, current_user)
    users = [u for u in await _get_users_by_ids_api(db, ids) if u.is_active]
    for user in users:
        user.is_active = False
    await db.commit()
    for user in users:
        await revoke_all_sessions_for_user(db, user.id)
    await log_event(
        db,
        request=request,
        action="users.bulk.deactivate",
        summary=f"Deactivated {len(users)} selected user(s)",
        details={"usernames": [u.username for u in users]},
    )
    return {"deactivated": len(users)}


@router.post("/bulk/activate", dependencies=[_manage])
async def bulk_activate_users_api(
    request: Request,
    payload: _BulkUserIds,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_api_permission(Permission.USER_MANAGE)),
) -> dict[str, object]:
    ids = _bulk_user_ids(payload, current_user)
    users = [u for u in await _get_users_by_ids_api(db, ids) if not u.is_active]
    for user in users:
        user.is_active = True
    await db.commit()
    await log_event(
        db,
        request=request,
        action="users.bulk.activate",
        summary=f"Activated {len(users)} selected user(s)",
        details={"usernames": [u.username for u in users]},
    )
    return {"activated": len(users)}


@router.post("/bulk/sessions/revoke-all", dependencies=[_manage])
async def bulk_revoke_user_sessions_api(
    request: Request,
    payload: _BulkUserIds,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_api_permission(Permission.USER_MANAGE)),
) -> dict[str, object]:
    ids = _bulk_user_ids(payload, current_user)
    users = await _get_users_by_ids_api(db, ids)
    for user in users:
        await revoke_all_sessions_for_user(db, user.id)
    await log_event(
        db,
        request=request,
        action="users.bulk.sign_out",
        summary=f"Force-logged-out {len(users)} selected user(s)",
        details={"usernames": [u.username for u in users]},
    )
    return {"signed_out": len(users)}


@router.post("/bulk/role", dependencies=[_manage])
async def bulk_set_role_api(
    request: Request,
    payload: _BulkSetRole,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_api_permission(Permission.USER_MANAGE)),
) -> dict[str, object]:
    role = await db.get(Role, payload.role_id)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Selected role does not exist.",
        )
    ids = _bulk_user_ids(payload, current_user)
    users = await _get_users_by_ids_api(db, ids)
    for user in users:
        user.role_id = role.id
    await db.commit()
    await log_event(
        db,
        request=request,
        action="users.bulk.role",
        summary=f'Set role "{role.name}" for {len(users)} selected user(s)',
        details={"role": role.name, "usernames": [u.username for u in users]},
    )
    return {"updated": len(users)}


@router.post("/{user_id}/deactivate", dependencies=[_manage])
async def deactivate_user_api(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_api_permission(Permission.USER_MANAGE)),
) -> dict[str, object]:
    user = await _get_user_or_404(user_id, db)
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="You can't deactivate your own account."
        )
    if await _would_remove_last_admin(db, user):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This is the last account that can manage users — it can't be deactivated.",
        )
    user.is_active = False
    await db.commit()
    await revoke_all_sessions_for_user(db, user.id)
    await log_event(
        db,
        request=request,
        action="user.update",
        summary=f'Deactivated user "{user.username}"',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return _user_to_dict(user)


class _ResetPasswordBody(BaseModel):
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=255)


@router.post("/{user_id}/reset-password", dependencies=[_manage])
async def reset_password_api(
    request: Request,
    user_id: uuid.UUID,
    payload: _ResetPasswordBody,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    user = await _get_user_or_404(user_id, db)
    if user.auth_provider != AuthProvider.LOCAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only local accounts have a debcontrol password to reset.",
        )
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = True
    await db.commit()
    await revoke_all_sessions_for_user(db, user.id)
    await log_event(
        db,
        request=request,
        action="user.password.reset",
        summary=f'Reset password for "{user.username}" (forced to change it on next login)',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return {"ok": True}


@router.post("/{user_id}/sessions/revoke-all", dependencies=[_manage])
async def revoke_user_sessions_api(
    request: Request, user_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    user = await _get_user_or_404(user_id, db)
    await revoke_all_sessions_for_user(db, user.id)
    await log_event(
        db,
        request=request,
        action="user.sessions.revoke_all",
        summary=f'Logged out all sessions for "{user.username}"',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return {"ok": True}


class _ConfirmDeleteUser(BaseModel):
    confirm_username: str = Field(min_length=1)


@router.delete("/{user_id}", dependencies=[_manage])
async def delete_user_api(
    request: Request,
    user_id: uuid.UUID,
    payload: _ConfirmDeleteUser,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_api_permission(Permission.USER_MANAGE)),
) -> Response:
    user = await _get_user_or_404(user_id, db)
    if payload.confirm_username.strip() != user.username:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f'"confirm_username" must exactly match the user\'s username '
                f'("{user.username}").'
            ),
        )
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="You can't delete your own account."
        )
    if await _would_remove_last_admin(db, user):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This is the last account that can manage users — it can't be deleted.",
        )

    username = user.username
    await db.delete(user)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.delete",
        summary=f'Deleted user "{username}"',
        target_type="user",
        target_id=user_id,
        target_label=username,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _grant_to_dict(grant: TemporaryPermissionGrant) -> dict[str, object]:
    return {
        "id": str(grant.id),
        "permission": grant.permission.value,
        "granted_by_id": str(grant.granted_by_id) if grant.granted_by_id else None,
        "granted_at": grant.granted_at.isoformat(),
        "expires_at": grant.expires_at.isoformat(),
        "revoked_at": grant.revoked_at.isoformat() if grant.revoked_at else None,
        "is_active": grant.is_active,
    }


@router.get("/{user_id}/temporary-permissions", dependencies=[_manage])
async def list_temporary_permissions_api(
    user_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> list[dict[str, object]]:
    await _get_user_or_404(user_id, db)
    grants = await list_temporary_grants(db, user_id)
    return [_grant_to_dict(g) for g in grants]


class _GrantTemporaryPermission(BaseModel):
    permission: Permission
    hours: int = Field(gt=0, le=MAX_GRANT_HOURS)


@router.post(
    "/{user_id}/temporary-permissions",
    dependencies=[_manage],
    status_code=status.HTTP_201_CREATED,
)
async def grant_temporary_permission_api(
    request: Request,
    user_id: uuid.UUID,
    payload: _GrantTemporaryPermission,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_api_permission(Permission.USER_MANAGE)),
) -> dict[str, object]:
    """A permission on top of whatever the account's role already grants,
    expiring on its own after `hours` — see
    `app.services.temporary_permissions` and `User.has_permission`."""
    user = await _get_user_or_404(user_id, db)
    grant = await grant_temporary_permission(
        db,
        user_id=user.id,
        permission=payload.permission,
        hours=payload.hours,
        granted_by_id=current_user.id,
    )
    await log_event(
        db,
        request=request,
        action="user.temporary_permission.grant",
        summary=(
            f'Granted "{user.username}" {payload.permission.value} for {payload.hours}h '
            f'(until {grant.expires_at.strftime("%Y-%m-%d %H:%M UTC")})'
        ),
        target_type="user",
        target_id=user.id,
        target_label=user.username,
        details={
            "permission": payload.permission.value,
            "hours": payload.hours,
            "expires_at": grant.expires_at.isoformat(),
        },
    )
    return _grant_to_dict(grant)


@router.delete("/{user_id}/temporary-permissions/{grant_id}", dependencies=[_manage])
async def revoke_temporary_permission_api(
    request: Request,
    user_id: uuid.UUID,
    grant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await _get_user_or_404(user_id, db)
    grant = await revoke_temporary_grant(db, user_id=user.id, grant_id=grant_id)
    if grant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active temporary permission grant with that id.",
        )
    await log_event(
        db,
        request=request,
        action="user.temporary_permission.revoke",
        summary=f'Revoked "{user.username}"\'s temporary {grant.permission.value} early',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
        details={"permission": grant.permission.value},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
