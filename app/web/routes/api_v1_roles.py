"""REST API for roles — mirrors `app/web/routes/roles.py`, including the
same "don't strip the last account's ability to manage users" guardrail
(`app.auth.login.count_active_users_with_permission`, reused directly)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_api_permission
from app.auth.login import count_active_users_with_permission
from app.db.models.role import Permission, Role, RolePermission
from app.db.session import get_db
from app.schemas.role import RoleSave

router = APIRouter(prefix="/api/v1/roles")

_manage = Depends(require_api_permission(Permission.USER_MANAGE))


def _role_to_dict(role: Role) -> dict[str, object]:
    return {
        "id": str(role.id),
        "name": role.name,
        "description": role.description,
        "permissions": sorted(p.value for p in role.permissions),
        "user_count": len(role.users),
    }


async def _get_role_or_404(role_id: uuid.UUID, db: AsyncSession) -> Role:
    result = await db.execute(
        select(Role).options(selectinload(Role.users)).where(Role.id == role_id)
    )
    role = result.scalar_one_or_none()
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")
    return role


@router.get("", dependencies=[_manage])
async def list_roles_api(db: AsyncSession = Depends(get_db)) -> list[dict[str, object]]:
    result = await db.execute(select(Role).options(selectinload(Role.users)).order_by(Role.name))
    return [_role_to_dict(r) for r in result.scalars().all()]


@router.get("/{role_id}", dependencies=[_manage])
async def get_role_api(role_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    return _role_to_dict(await _get_role_or_404(role_id, db))


@router.post("", dependencies=[_manage], status_code=status.HTTP_201_CREATED)
async def create_role_api(
    request: Request, payload: RoleSave, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    role = Role(name=payload.name, description=payload.description)
    role.permission_grants = [RolePermission(permission=p) for p in payload.permissions]
    db.add(role)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'A role named "{payload.name}" already exists.',
        ) from None
    role = await _get_role_or_404(role.id, db)
    await log_event(
        db,
        request=request,
        action="role.create",
        summary=f'Created role "{role.name}" ({len(payload.permissions)} permission(s))',
        target_type="role",
        target_id=role.id,
        target_label=role.name,
    )
    return _role_to_dict(role)


@router.put("/{role_id}", dependencies=[_manage])
async def update_role_api(
    request: Request, role_id: uuid.UUID, payload: RoleSave, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    role = await _get_role_or_404(role_id, db)

    if (
        Permission.USER_MANAGE in role.permissions
        and Permission.USER_MANAGE not in payload.permissions
    ):
        remaining = await count_active_users_with_permission(
            db, Permission.USER_MANAGE, excluding_role_id=role.id
        )
        if remaining == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Can't remove 'user.manage' from this role — no other active account "
                    "would be able to manage users afterwards."
                ),
            )

    role.name = payload.name
    role.description = payload.description
    role.permission_grants = [RolePermission(permission=p) for p in payload.permissions]

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'A role named "{payload.name}" already exists.',
        ) from None

    role = await _get_role_or_404(role.id, db)
    await log_event(
        db,
        request=request,
        action="role.update",
        summary=f'Updated role "{role.name}" ({len(payload.permissions)} permission(s))',
        target_type="role",
        target_id=role.id,
        target_label=role.name,
    )
    return _role_to_dict(role)


@router.delete("/{role_id}", dependencies=[_manage])
async def delete_role_api(
    request: Request, role_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    role = await _get_role_or_404(role_id, db)
    if role.users:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f'"{role.name}" is assigned to {len(role.users)} user(s) — reassign them first.'
            ),
        )
    role_name = role.name
    await db.delete(role)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="role.delete",
        summary=f'Deleted role "{role_name}"',
        target_type="role",
        target_id=role_id,
        target_label=role_name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
