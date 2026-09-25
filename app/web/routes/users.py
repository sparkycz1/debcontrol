"""User accounts — CRUD, password resets, and forcing a re-login.

Every route here requires `user.manage` (checked at the router level) — see
`app/db/models/role.py`. Several routes additionally protect against
locking everyone out of user management: you can't deactivate, delete, or
demote your own account, and the last active account holding `user.manage`
can't be deactivated, deleted, or demoted away from it either (see
`app.auth.login.count_active_users_with_permission`).

This is also where an account's **machine-group scope** is set (the
checkbox list on the create/edit forms): which groups it may see at all,
independent of what its role lets it do. That's account administration in
exactly the same sense as `User.api_access_enabled`, so it's gated by the
existing `user.manage` rather than a `Permission` of its own — see
`app.services.access_scope` and `app.db.models.user_machine_group_access`.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.auth.login import count_active_users_with_permission
from app.auth.security import hash_password
from app.auth.sessions import revoke_all_sessions_for_user
from app.core.csrf import verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission, Role
from app.db.models.user import AuthProvider, User, role_has_permission
from app.db.session import get_db
from app.schemas.user import UserCreate, UserUpdate
from app.services.access_scope import (
    allowed_group_ids,
    group_names_for,
    set_group_access,
)
from app.services.temporary_permissions import (
    MAX_GRANT_HOURS,
    grant_temporary_permission,
    list_temporary_grants,
    revoke_temporary_grant,
)
from app.web.flash import read_flash, sign_flash
from app.web.templating import t, templates

router = APIRouter(
    prefix="/users", dependencies=[Depends(require_permission(Permission.USER_MANAGE))]
)


async def _get_user_or_404(user_id: uuid.UUID, db: AsyncSession) -> User:
    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user


async def _duplicate_user_error(
    request: Request,
    db: AsyncSession,
    *,
    exclude_user_id: uuid.UUID,
    username: str,
    email: str | None,
) -> str | None:
    """Proactively look for a row this write would collide with, instead of
    relying on catching `IntegrityError` from the commit.

    This matters specifically for *updates*, not creates: `User.updated_at`
    has `onupdate=func.now()`, so SQLAlchemy emits an implicit
    `UPDATE ... RETURNING updated_at`. Confirmed against both dialects:
    asyncpg (what production actually runs — see `app.core.config`) handles
    a UNIQUE-violating RETURNING UPDATE the same way as any other failed
    statement, surfacing a normal `IntegrityError`. But under the test
    suite's aiosqlite backend (`tests/conftest.py`'s `db_session_factory`),
    the same failure corrupts aiosqlite's greenlet/asyncio bridging and
    surfaces as `sqlalchemy.exc.MissingGreenlet` instead — a driver-level
    quirk, not a real production behavior. This check sidesteps it so the
    common "edited to someone else's username/email" case behaves
    identically on both backends; the `IntegrityError` catch below the
    commit stays in place as a defense-in-depth backstop for a genuine
    create/update race.
    """
    conditions = [User.username == username]
    if email:
        conditions.append(User.email == email)
    result = await db.execute(select(User).where(User.id != exclude_user_id, or_(*conditions)))
    conflict = result.scalars().first()
    if conflict is None:
        return None
    if conflict.username == username:
        return t(request, "users.error.username_taken", username=username)
    return t(request, "account.error.email_in_use")


async def _get_roles(db: AsyncSession) -> list[Role]:
    result = await db.execute(select(Role).order_by(Role.name))
    return list(result.scalars().all())


async def _get_all_groups(db: AsyncSession) -> list[MachineGroup]:
    """Every machine group, for the scope checkbox list. Deliberately *not*
    scoped to the acting admin: `user.manage` is account administration, and
    an admin who could only grant the groups they personally see would be a
    surprising, half-working control. (An admin can't change their own scope
    at all — see `update_user`.)"""
    result = await db.execute(select(MachineGroup).order_by(MachineGroup.name))
    return list(result.scalars().all())


async def _parse_group_access(
    request: Request, db: AsyncSession, raw_group_ids: list[str]
) -> tuple[list[uuid.UUID], str | None]:
    """Turn the submitted checkbox values into group ids, or an error
    message. An unparseable/unknown id means a tampered form (the list is
    server-rendered), so it's rejected rather than silently dropped —
    silently narrowing somebody's scope is exactly the kind of quiet
    failure a security boundary shouldn't have."""
    parsed: list[uuid.UUID] = []
    for raw in raw_group_ids:
        if not raw.strip():
            continue
        try:
            parsed.append(uuid.UUID(raw.strip()))
        except ValueError:
            return [], t(request, "users.error.group_invalid")
    if not parsed:
        return [], None
    known = set(
        (
            await db.execute(select(MachineGroup.id).where(MachineGroup.id.in_(parsed)))
        )
        .scalars()
        .all()
    )
    missing = [gid for gid in parsed if gid not in known]
    if missing:
        return [], t(request, "users.error.group_gone")
    return list(dict.fromkeys(parsed)), None


async def _log_group_access_change(
    db: AsyncSession, request: Request, user: User, group_ids: list[uuid.UUID]
) -> None:
    names = await group_names_for(db, group_ids)
    scope = ", ".join(names) if names else "full access (no group restriction)"
    await log_event(
        db,
        request=request,
        action="user.group_access.update",
        summary=f'Set machine-group access for "{user.username}" to {scope}',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
        details={"groups": names},
    )


async def _get_users_by_ids(
    db: AsyncSession, user_ids: list[uuid.UUID], *, exclude: uuid.UUID
) -> list[User]:
    """The submitted selection, minus the acting admin's own account —
    silently dropped, the same "never let a bulk action touch the actor's
    own row" rule `update_user` enforces one at a time (you can't change
    your own role, deactivate yourself, ...). Client-submitted ids beyond
    that are trusted as-is: unlike the machine list's bulk actions, the
    user list has no per-account visibility scoping to re-check here.

    This is also why none of the bulk actions below need their own
    "would this remove the last admin" check the way `update_user`/
    `delete_user` do for a single account: every route in this router
    already requires `user.manage` (see the router's own dependency), so
    the acting account always holds it — and since that account's own row
    is never in the batch, at least one active `user.manage` holder (the
    actor) is always left standing no matter what the batch does to
    everyone else."""
    ids = [uid for uid in user_ids if uid != exclude]
    if not ids:
        return []
    result = await db.execute(select(User).options(selectinload(User.role)).where(User.id.in_(ids)))
    return list(result.scalars().all())


async def _would_remove_last_admin(db: AsyncSession, target: User) -> bool:
    if not target.has_permission(Permission.USER_MANAGE):
        return False
    remaining = await count_active_users_with_permission(
        db, Permission.USER_MANAGE, excluding_user_id=target.id
    )
    return remaining == 0


@router.get("")
async def list_users(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(select(User).options(selectinload(User.role)).order_by(User.username))
    users = result.scalars().all()
    return templates.TemplateResponse(
        request,
        "users/list.html",
        {
            "users": users,
            "roles": await _get_roles(db),
            "csrf_token": request.state.csrf_token,
            "bulk_error": read_flash(request, "bulk_error"),
        },
    )


@router.get("/new")
async def new_user_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    return templates.TemplateResponse(
        request,
        "users/new.html",
        {
            "roles": await _get_roles(db),
            "auth_providers": list(AuthProvider),
            "all_groups": await _get_all_groups(db),
            "selected_group_ids": [],
            "errors": [],
            "form": {},
            "csrf_token": request.state.csrf_token,
        },
    )


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    username: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    auth_provider: AuthProvider = Form(...),
    password: str = Form(""),
    role_id: str = Form(...),
    api_access_enabled: str = Form(""),
    group_access: list[str] = Form(default=[]),
) -> Response:
    async def _rerender(errors: list[str], status_code: int) -> Response:
        await log_event(
            db,
            request=request,
            action="user.create",
            summary=f'Rejected new user "{username}": {"; ".join(errors)}',
            outcome=AuditOutcome.FAILURE,
        )
        return templates.TemplateResponse(
            request,
            "users/new.html",
            {
                "roles": await _get_roles(db),
                "auth_providers": list(AuthProvider),
                "all_groups": await _get_all_groups(db),
                "selected_group_ids": group_access,
                "errors": errors,
                "form": {
                    "username": username,
                    "display_name": display_name,
                    "email": email,
                    "auth_provider": auth_provider,
                    "role_id": role_id,
                },
                "csrf_token": request.state.csrf_token,
            },
            status_code=status_code,
        )

    scoped_group_ids, group_error = await _parse_group_access(request, db, group_access)
    if group_error is not None:
        return await _rerender([group_error], status.HTTP_422_UNPROCESSABLE_CONTENT)

    try:
        role_uuid = uuid.UUID(role_id)
        payload = UserCreate(
            username=username,
            display_name=display_name or None,
            email=email or None,
            auth_provider=auth_provider,
            password=password or None,
            role_id=role_uuid,
            api_access_enabled=bool(api_access_enabled),
        )
    except ValueError as exc:
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    role = await db.get(Role, payload.role_id)
    if role is None:
        return await _rerender(
            [t(request, "users.error.role_gone")], status.HTTP_422_UNPROCESSABLE_CONTENT
        )

    user = User(
        username=payload.username,
        display_name=payload.display_name,
        email=payload.email,
        auth_provider=payload.auth_provider,
        password_hash=hash_password(payload.password) if payload.password else None,
        # An admin-set initial password must be changed on first login —
        # nobody but the account owner should keep using a password someone
        # else picked and now knows.
        must_change_password=payload.auth_provider == AuthProvider.LOCAL,
        role_id=payload.role_id,
        api_access_enabled=payload.api_access_enabled,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        # Could be the username or the email unique constraint — either way
        # the account wasn't created, and there's no cheap way to tell which
        # column tripped from a generic IntegrityError without inspecting
        # driver-specific error text, so the message covers both.
        return await _rerender(
            [
                f'A user named "{payload.username}" already exists, '
                "or that email is already in use by another account."
            ],
            status.HTTP_409_CONFLICT,
        )
    await db.refresh(user)

    await log_event(
        db,
        request=request,
        action="user.create",
        summary=f'Created user "{user.username}" ({user.auth_provider.value}, role "{role.name}")',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    if scoped_group_ids:
        await set_group_access(db, user.id, scoped_group_ids)
        await db.commit()
        await _log_group_access_change(db, request, user, scoped_group_ids)
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{user_id}/edit")
async def edit_user_form(
    request: Request, user_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    user = await _get_user_or_404(user_id, db)
    return templates.TemplateResponse(
        request,
        "users/edit.html",
        {
            "target_user": user,
            "roles": await _get_roles(db),
            "auth_providers": list(AuthProvider),
            "all_groups": await _get_all_groups(db),
            "selected_group_ids": [str(gid) for gid in (await allowed_group_ids(db, user) or [])],
            "all_permissions": list(Permission),
            "temporary_grants": await list_temporary_grants(db, user.id),
            "max_grant_hours": MAX_GRANT_HOURS,
            "errors": [],
            "csrf_token": request.state.csrf_token,
        },
    )


@router.post("/{user_id}/edit", dependencies=[Depends(verify_csrf)])
async def update_user(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    username: str = Form(...),
    display_name: str = Form(""),
    email: str = Form(""),
    auth_provider: AuthProvider = Form(...),
    password: str = Form(""),
    role_id: str = Form(...),
    is_active: str = Form(""),
    api_access_enabled: str = Form(""),
    group_access: list[str] = Form(default=[]),
) -> Response:
    user = await _get_user_or_404(user_id, db)
    current_group_ids = await allowed_group_ids(db, user) or set()

    async def _rerender(errors: list[str], status_code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "users/edit.html",
            {
                "target_user": user,
                "roles": await _get_roles(db),
                "auth_providers": list(AuthProvider),
                "all_groups": await _get_all_groups(db),
                "selected_group_ids": group_access,
                "errors": errors,
                "csrf_token": request.state.csrf_token,
            },
            status_code=status_code,
        )

    scoped_group_ids, group_error = await _parse_group_access(request, db, group_access)
    if group_error is not None:
        return await _rerender([group_error], status.HTTP_422_UNPROCESSABLE_CONTENT)
    group_access_changed = set(scoped_group_ids) != current_group_ids

    try:
        role_uuid = uuid.UUID(role_id)
        payload = UserUpdate(
            username=username,
            display_name=display_name or None,
            email=email or None,
            auth_provider=auth_provider,
            password=password or None,
            role_id=role_uuid,
            is_active=bool(is_active),
            api_access_enabled=bool(api_access_enabled),
        )
    except ValueError as exc:
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    role = await db.get(Role, payload.role_id)
    if role is None:
        return await _rerender(
            [t(request, "users.error.role_gone")], status.HTTP_422_UNPROCESSABLE_CONTENT
        )

    if user.id == current_user.id:
        if payload.role_id != user.role_id:
            return await _rerender(
                [t(request, "users.error.own_role")],
                status.HTTP_403_FORBIDDEN,
            )
        if not payload.is_active:
            return await _rerender(
                [t(request, "users.error.own_deactivate")], status.HTTP_403_FORBIDDEN
            )
        # Same reasoning as the self-role-change guard directly above: an
        # admin editing something unrelated must not be able to lock
        # themselves out of most of the fleet in passing. Another
        # administrator can still do it.
        if group_access_changed:
            return await _rerender(
                [
                    "You can't change your own machine-group access — "
                    "ask another administrator."
                ],
                status.HTTP_403_FORBIDDEN,
            )

    becoming_local = payload.auth_provider == AuthProvider.LOCAL
    losing_local = user.auth_provider == AuthProvider.LOCAL and not becoming_local
    if becoming_local and user.auth_provider != AuthProvider.LOCAL and not payload.password:
        return await _rerender(
            [f'Switching "{user.username}" to a local account needs a password.'],
            status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    # Would this change (deactivating, or moving off the role that grants
    # user.manage) leave nobody able to manage users?
    still_has_user_manage = payload.is_active and role_has_permission(role, Permission.USER_MANAGE)
    if user.has_permission(Permission.USER_MANAGE) and not still_has_user_manage:
        remaining = await count_active_users_with_permission(
            db, Permission.USER_MANAGE, excluding_user_id=user.id
        )
        if remaining == 0:
            return await _rerender(
                [t(request, "users.error.last_admin")],
                status.HTTP_409_CONFLICT,
            )

    # Checked before mutating `user` in place below: once its attributes are
    # dirtied, a `SELECT` here would trigger autoflush and emit the very
    # UPDATE this check exists to get ahead of, defeating the point (see
    # `_duplicate_user_error`'s docstring).
    duplicate_error = await _duplicate_user_error(
        request,
        db, exclude_user_id=user.id, username=payload.username, email=payload.email
    )
    if duplicate_error is not None:
        return await _rerender([duplicate_error], status.HTTP_409_CONFLICT)

    user.username = payload.username
    user.display_name = payload.display_name
    user.email = payload.email
    user.auth_provider = payload.auth_provider
    user.role_id = payload.role_id
    user.is_active = payload.is_active
    user.api_access_enabled = payload.api_access_enabled
    if becoming_local and payload.password:
        user.password_hash = hash_password(payload.password)
        user.must_change_password = True
        # else: switching TO local with no password only reaches here if it
        # was already local (blank = keep existing hash unchanged).
    if losing_local:
        user.password_hash = None
        user.must_change_password = False

    if group_access_changed:
        await set_group_access(db, user.id, scoped_group_ids)

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _rerender(
            [
                f'A user named "{payload.username}" already exists, '
                "or that email is already in use by another account."
            ],
            status.HTTP_409_CONFLICT,
        )

    if not payload.is_active:
        # Cut access immediately rather than waiting for existing sessions
        # to expire on their own.
        await revoke_all_sessions_for_user(db, user.id)

    await log_event(
        db,
        request=request,
        action="user.update",
        summary=f'Updated user "{user.username}"',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    if group_access_changed:
        await _log_group_access_change(db, request, user, scoped_group_ids)
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/temporary-permissions", dependencies=[Depends(verify_csrf)])
async def grant_temporary_permission_endpoint(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    permission: str = Form(...),
    hours: str = Form(...),
) -> Response:
    """"Časově omezený přístup" — a temporary permission on top of
    whatever the account's role already grants, expiring on its own after
    `hours` (see `app.services.temporary_permissions` and
    `User.has_permission`). No confirmation phrase needed: unlike a
    permanent role change, this already carries its own built-in undo."""
    user = await _get_user_or_404(user_id, db)

    def _error_redirect(message: str) -> Response:
        return RedirectResponse(
            url=f"/users/{user.id}/edit?perm_error={sign_flash(message)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        parsed_permission = Permission(permission)
    except ValueError:
        return _error_redirect(t(request, "users.error.unknown_permission"))
    try:
        parsed_hours = int(hours)
        if not (0 < parsed_hours <= MAX_GRANT_HOURS):
            raise ValueError
    except ValueError:
        return _error_redirect(t(request, "users.error.grant_duration", max=MAX_GRANT_HOURS))

    grant = await grant_temporary_permission(
        db,
        user_id=user.id,
        permission=parsed_permission,
        hours=parsed_hours,
        granted_by_id=current_user.id,
    )
    await log_event(
        db,
        request=request,
        action="user.temporary_permission.grant",
        summary=(
            f'Granted "{user.username}" {parsed_permission.value} for {parsed_hours}h '
            f'(until {grant.expires_at.strftime("%Y-%m-%d %H:%M UTC")})'
        ),
        target_type="user",
        target_id=user.id,
        target_label=user.username,
        details={
            "permission": parsed_permission.value,
            "hours": parsed_hours,
            "expires_at": grant.expires_at.isoformat(),
        },
    )
    return RedirectResponse(url=f"/users/{user.id}/edit", status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/{user_id}/temporary-permissions/{grant_id}/revoke", dependencies=[Depends(verify_csrf)]
)
async def revoke_temporary_permission_endpoint(
    request: Request,
    user_id: uuid.UUID,
    grant_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await _get_user_or_404(user_id, db)
    grant = await revoke_temporary_grant(db, user_id=user.id, grant_id=grant_id)
    if grant is not None:
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
    return RedirectResponse(url=f"/users/{user.id}/edit", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/reset-password", dependencies=[Depends(verify_csrf)])
async def reset_password(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    new_password: str = Form(...),
) -> Response:
    user = await _get_user_or_404(user_id, db)
    if user.auth_provider != AuthProvider.LOCAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only local accounts have a debcontrol password to reset.",
        )
    if len(new_password) < 12:
        return templates.TemplateResponse(
            request,
            "users/edit.html",
            {
                "target_user": user,
                "roles": await _get_roles(db),
                "auth_providers": list(AuthProvider),
                "all_groups": await _get_all_groups(db),
                "selected_group_ids": [
                    str(gid) for gid in (await allowed_group_ids(db, user) or [])
                ],
                "errors": [t(request, "users.error.password_too_short", min=12)],
                "csrf_token": request.state.csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    user.password_hash = hash_password(new_password)
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
    return RedirectResponse(url=f"/users/{user.id}/edit", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/sessions/revoke-all", dependencies=[Depends(verify_csrf)])
async def revoke_user_sessions(
    request: Request, user_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
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
    return RedirectResponse(url=f"/users/{user.id}/edit", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_user(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    user = await _get_user_or_404(user_id, db)
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
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


# --- Bulk actions (ad-hoc selection from the user list) --------------------
#
# Same "one selection, several possible actions, one shared form" shape as
# `app/web/routes/machines.py`'s bulk actions — with one addition none of
# those need: the acting admin's own row is always dropped from the
# selection first (see `_get_users_by_ids`, whose own docstring is also why
# none of these need their own "last admin" guard). Deliberately no bulk
# delete here: unlike deactivate (fully reversible from this same page) a
# bulk delete is destructive and irreversible, and the existing
# single-account delete already needs its own confirmation dialog for
# exactly that reason — a bulk version would need the same
# typed-confirmation treatment `machines.py`'s bulk power actions get,
# which is more than this round adds.

def _bulk_error_url(request: Request, key: str) -> str:
    return f"/users?bulk_error={sign_flash(t(request, key))}"


@router.post("/bulk/deactivate", dependencies=[Depends(verify_csrf)])
async def bulk_deactivate_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_ids: list[uuid.UUID] = Form(default=[]),
) -> Response:
    selected = await _get_users_by_ids(db, user_ids, exclude=current_user.id)
    users = [u for u in selected if u.is_active]
    if not users:
        return RedirectResponse(
            url=_bulk_error_url(request, "users.error.select_other_user"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    for user in users:
        user.is_active = False
    await db.commit()
    for user in users:
        # Cut access immediately, same as the single-account version —
        # don't wait for existing sessions to expire on their own.
        await revoke_all_sessions_for_user(db, user.id)

    await log_event(
        db,
        request=request,
        action="users.bulk.deactivate",
        summary=f"Deactivated {len(users)} selected user(s)",
        details={"usernames": [u.username for u in users]},
    )
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/activate", dependencies=[Depends(verify_csrf)])
async def bulk_activate_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_ids: list[uuid.UUID] = Form(default=[]),
) -> Response:
    users = [
        u for u in await _get_users_by_ids(db, user_ids, exclude=current_user.id) if not u.is_active
    ]
    if not users:
        return RedirectResponse(
            url=_bulk_error_url(request, "users.error.select_other_user"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

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
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/sign-out", dependencies=[Depends(verify_csrf)])
async def bulk_sign_out_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_ids: list[uuid.UUID] = Form(default=[]),
) -> Response:
    users = await _get_users_by_ids(db, user_ids, exclude=current_user.id)
    if not users:
        return RedirectResponse(
            url=_bulk_error_url(request, "users.error.select_other_user"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    for user in users:
        await revoke_all_sessions_for_user(db, user.id)

    await log_event(
        db,
        request=request,
        action="users.bulk.sign_out",
        summary=f"Force-logged-out {len(users)} selected user(s)",
        details={"usernames": [u.username for u in users]},
    )
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/role", dependencies=[Depends(verify_csrf)])
async def bulk_set_role(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    user_ids: list[uuid.UUID] = Form(default=[]),
    role_id: str = Form(...),
) -> Response:
    users = await _get_users_by_ids(db, user_ids, exclude=current_user.id)
    if not users:
        return RedirectResponse(
            url=_bulk_error_url(request, "users.error.select_other_user"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        role = await db.get(Role, uuid.UUID(role_id))
    except ValueError:
        role = None
    if role is None:
        return RedirectResponse(
            url=_bulk_error_url(request, "users.error.role_gone"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

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
    return RedirectResponse(url="/users", status_code=status.HTTP_303_SEE_OTHER)
