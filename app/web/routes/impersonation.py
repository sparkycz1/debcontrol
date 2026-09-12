"""Impersonation ("sign in as another account") — `user.impersonate`.

Deliberately its own module/permission, not folded into `app.web.routes.
users` (which requires `user.manage`): editing accounts and roles is one
trust level, silently *acting as* one of them is a materially bigger one.

How it works: starting an impersonation does **not** touch the admin's own
session row — it creates a brand-new `UserSession` for the target account
(tagged `impersonator_id`), swaps the browser's session cookie over to it,
and stashes the admin's own raw session token in a second, signed,
httponly cookie (`impersonation_return`) so it can be handed back
untouched later. Nothing about the admin's original session is revoked or
extended by any of this.

Ending it is folded into the existing `/logout` route (see
`app.web.routes.auth.logout`) rather than a separate endpoint: logging out
of an impersonated session restores the admin's own session instead of
signing them out entirely, exactly like closing a "su" shell — see that
route for the exact fallback behavior if the return ticket has expired or
the original session no longer validates (a plain, full logout).

Every start/stop is audit-logged under both identities (`user.impersonate.
start`/`user.impersonate.stop`), and every action taken *during* an
impersonated session is already audit-logged as usual under the
impersonated account — `request.state.impersonator` (set by
`app.auth.middleware`) is available to any call site that wants to record
who was really behind the wheel, same as the topbar banner uses it purely
for display (see `base.html`).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_permission
from app.auth.sessions import (
    SESSION_COOKIE_NAME,
    create_impersonation_return_ticket,
    set_impersonation_return_cookie,
    set_session_cookie,
    start_impersonation,
)
from app.core.csrf import verify_csrf
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db

router = APIRouter(dependencies=[Depends(require_permission(Permission.USER_IMPERSONATE))])


@router.post(
    "/users/{user_id}/impersonate",
    dependencies=[Depends(verify_csrf)],
)
async def start_impersonating(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    admin: User = request.state.user
    session = request.state.session

    if session.impersonator_id is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Already impersonating someone — stop first (log out) before starting another.",
        )
    if user_id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="You can't impersonate yourself.")

    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.id == user_id)
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found.")
    if not target.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That account is disabled.")
    if target.has_permission(Permission.USER_IMPERSONATE):
        # Guards against an impersonation chain/loop and against one admin
        # silently acting as another admin-equivalent account — the target
        # of an impersonation is never itself allowed to start one.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="Can't impersonate an account that can itself impersonate others.",
        )

    raw_admin_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_admin_token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    await log_event(
        db,
        request=request,
        action="user.impersonate.start",
        summary=f'"{admin.username}" started impersonating "{target.username}"',
        target_type="user",
        target_id=target.id,
        target_label=target.username,
    )

    _, raw_impersonation_token = await start_impersonation(
        db,
        admin=admin,
        target=target,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    set_impersonation_return_cookie(response, create_impersonation_return_ticket(raw_admin_token))
    set_session_cookie(response, raw_impersonation_token)
    return response
