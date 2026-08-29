"""Roles — named, reusable permission sets (see `app/db/models/role.py`).

Every route here requires `user.manage`, same as `app/web/routes/users.py` —
see that module's docstring for why the two are bundled under one
permission. A role can't be deleted while any user still holds it (enforced
both by the DB's `ON DELETE RESTRICT` and, for a friendlier error, checked
here first), and a role's permissions can't be edited in a way that would
leave nobody able to manage users (see
`app.auth.login.count_active_users_with_permission`).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_permission
from app.auth.login import count_active_users_with_permission
from app.core.csrf import verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.role import Permission, Role, RolePermission
from app.db.session import get_db
from app.schemas.role import RoleSave
from app.web.templating import templates

router = APIRouter(
    prefix="/roles", dependencies=[Depends(require_permission(Permission.USER_MANAGE))]
)


async def _get_role_or_404(role_id: uuid.UUID, db: AsyncSession) -> Role:
    result = await db.execute(
        select(Role).options(selectinload(Role.users)).where(Role.id == role_id)
    )
    role = result.scalar_one_or_none()
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")
    return role


def _permissions_from_values(values: list[str]) -> list[Permission]:
    permissions = []
    for value in values:
        try:
            permissions.append(Permission(value))
        except ValueError:
            continue
    return permissions


@router.get("")
async def list_roles(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(select(Role).options(selectinload(Role.users)).order_by(Role.name))
    roles = result.scalars().all()
    return templates.TemplateResponse(
        request, "roles/list.html", {"roles": roles, "csrf_token": request.state.csrf_token}
    )


@router.get("/new")
async def new_role_form(request: Request) -> Response:
    return templates.TemplateResponse(
        request,
        "roles/new.html",
        {
            "all_permissions": list(Permission),
            "errors": [],
            "form": {"name": "", "description": "", "permissions": []},
            "csrf_token": request.state.csrf_token,
        },
    )


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_role(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    form = await request.form()
    name = str(form.get("name", ""))
    description = str(form.get("description", ""))
    permission_values = [str(v) for v in form.getlist("permissions")]

    try:
        payload = RoleSave(
            name=name,
            description=description or None,
            permissions=_permissions_from_values(permission_values),
        )
    except ValueError as exc:
        await log_event(
            db,
            request=request,
            action="role.create",
            summary=f'Rejected new role "{name}": {exc}',
            outcome=AuditOutcome.FAILURE,
        )
        return templates.TemplateResponse(
            request,
            "roles/new.html",
            {
                "all_permissions": list(Permission),
                "errors": [str(exc)],
                "form": {
                    "name": name,
                    "description": description,
                    "permissions": permission_values,
                },
                "csrf_token": request.state.csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    role = Role(name=payload.name, description=payload.description)
    role.permission_grants = [RolePermission(permission=p) for p in payload.permissions]
    db.add(role)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return templates.TemplateResponse(
            request,
            "roles/new.html",
            {
                "all_permissions": list(Permission),
                "errors": [f'A role named "{payload.name}" already exists.'],
                "form": {
                    "name": name,
                    "description": description,
                    "permissions": permission_values,
                },
                "csrf_token": request.state.csrf_token,
            },
            status_code=status.HTTP_409_CONFLICT,
        )
    await db.refresh(role)

    await log_event(
        db,
        request=request,
        action="role.create",
        summary=f'Created role "{role.name}" ({len(payload.permissions)} permission(s))',
        target_type="role",
        target_id=role.id,
        target_label=role.name,
    )
    return RedirectResponse(url="/roles", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{role_id}/edit")
async def edit_role_form(
    request: Request, role_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    role = await _get_role_or_404(role_id, db)
    return templates.TemplateResponse(
        request,
        "roles/edit.html",
        {
            "role": role,
            "all_permissions": list(Permission),
            "current_permissions": role.permissions,
            "errors": [],
            "csrf_token": request.state.csrf_token,
        },
    )


@router.post("/{role_id}/edit", dependencies=[Depends(verify_csrf)])
async def update_role(
    request: Request, role_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    role = await _get_role_or_404(role_id, db)
    form = await request.form()
    name = str(form.get("name", ""))
    description = str(form.get("description", ""))
    permission_values = [str(v) for v in form.getlist("permissions")]

    def _rerender(errors: list[str], status_code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "roles/edit.html",
            {
                "role": role,
                "all_permissions": list(Permission),
                "current_permissions": set(_permissions_from_values(permission_values)),
                "errors": errors,
                "csrf_token": request.state.csrf_token,
            },
            status_code=status_code,
        )

    try:
        payload = RoleSave(
            name=name,
            description=description or None,
            permissions=_permissions_from_values(permission_values),
        )
    except ValueError as exc:
        return _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    if (
        Permission.USER_MANAGE in role.permissions
        and Permission.USER_MANAGE not in payload.permissions
    ):
        remaining = await count_active_users_with_permission(
            db, Permission.USER_MANAGE, excluding_role_id=role.id
        )
        if remaining == 0:
            return _rerender(
                [
                    "Can't remove 'user.manage' from this role — no other active account "
                    "would be able to manage users afterwards."
                ],
                status.HTTP_409_CONFLICT,
            )

    role.name = payload.name
    role.description = payload.description
    role.permission_grants = [RolePermission(permission=p) for p in payload.permissions]

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return _rerender(
            [f'A role named "{payload.name}" already exists.'], status.HTTP_409_CONFLICT
        )

    await log_event(
        db,
        request=request,
        action="role.update",
        summary=f'Updated role "{role.name}" ({len(payload.permissions)} permission(s))',
        target_type="role",
        target_id=role.id,
        target_label=role.name,
    )
    return RedirectResponse(url="/roles", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{role_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_role(
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
    return RedirectResponse(url="/roles", status_code=status.HTTP_303_SEE_OTHER)
