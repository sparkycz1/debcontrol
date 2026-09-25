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
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_permission
from app.auth.login import count_active_users_with_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.role import Permission, Role, RolePermission
from app.db.session import get_db
from app.schemas.role import RoleSave
from app.schemas.role_config import RoleConfigExport
from app.services.role_config import export_role_config, import_role_config
from app.web.templating import t, templates

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
            "form": {"name": "", "description": "", "permissions": [], "require_totp": False},
            "csrf_token": request.state.csrf_token,
        },
    )


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_role(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    form = await request.form()
    name = str(form.get("name", ""))
    description = str(form.get("description", ""))
    permission_values = [str(v) for v in form.getlist("permissions")]
    require_totp = bool(form.get("require_totp", ""))

    try:
        payload = RoleSave(
            name=name,
            description=description or None,
            permissions=_permissions_from_values(permission_values),
            require_totp=require_totp,
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
                    "require_totp": require_totp,
                },
                "csrf_token": request.state.csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    role = Role(
        name=payload.name, description=payload.description, require_totp=payload.require_totp
    )
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
                    "require_totp": require_totp,
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


@router.get("/config/export")
async def export_role_config_endpoint(
    request: Request, db: AsyncSession = Depends(get_db)
) -> Response:
    """Config-as-code export of every role and its permissions — same
    "structural config, JSON round-trip" convenience `GET
    /machines/config/export` gives machines/groups. See
    `app.services.role_config`."""
    export = await export_role_config(db)

    await log_event(
        db,
        request=request,
        action="role.config_export",
        summary=f"Exported configuration for {len(export.roles)} role(s)",
        details={"role_count": len(export.roles)},
    )

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=export.model_dump_json(indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="role-config-{timestamp}.json"'},
    )


@router.get("/config/import")
async def import_role_config_form(request: Request) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "roles/config_import.html",
        {"csrf_token": csrf_token, "errors": [], "result": None},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/config/import", dependencies=[Depends(verify_csrf)])
async def import_role_config_submit(
    request: Request, db: AsyncSession = Depends(get_db), json_text: str = Form("")
) -> Response:
    """Create real `Role`/`RolePermission` rows from a pasted JSON export
    (see `GET /roles/config/export`). See `app.services.role_config` for
    the conflict-handling policy."""
    text = json_text.strip()
    if not text:
        return templates.TemplateResponse(
            request,
            "roles/config_import.html",
            {
                "csrf_token": request.state.csrf_token,
                "errors": [t(request, "common.error.paste_json")],
                "result": None,
            },
        )

    try:
        payload = RoleConfigExport.model_validate_json(text)
    except ValidationError as exc:
        return templates.TemplateResponse(
            request,
            "roles/config_import.html",
            {
                "csrf_token": request.state.csrf_token,
                "errors": [f"Invalid configuration JSON: {exc}"],
                "result": None,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    result = await import_role_config(db, payload)

    await log_event(
        db,
        request=request,
        action="role.config_import",
        summary=result.summary(),
        details=result.to_dict(),
    )

    return templates.TemplateResponse(
        request,
        "roles/config_import.html",
        {"csrf_token": request.state.csrf_token, "errors": [], "result": result},
    )


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
            "require_totp": role.require_totp,
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
    require_totp = bool(form.get("require_totp", ""))

    def _rerender(errors: list[str], status_code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "roles/edit.html",
            {
                "role": role,
                "all_permissions": list(Permission),
                "current_permissions": set(_permissions_from_values(permission_values)),
                "require_totp": require_totp,
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
            require_totp=require_totp,
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
    role.require_totp = payload.require_totp
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
