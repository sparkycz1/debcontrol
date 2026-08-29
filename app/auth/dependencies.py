"""FastAPI dependencies for routes — `app.auth.middleware` already guarantees
every non-public request has a valid session and sets `request.state.user`
before a route ever runs; these just expose that typed, and enforce a
specific permission where a route needs more than "logged in"."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from app.db.models.role import Permission
from app.db.models.user import User


def get_current_user(request: Request) -> User:
    user: User | None = getattr(request.state, "user", None)
    if user is None:
        # Shouldn't happen on any route reachable via the middleware's
        # allowlist logic — this is a defensive fallback, not the normal
        # "please log in" path (that's a redirect, handled in the middleware).
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    return user


def require_permission(permission: Permission) -> Callable[[User], User]:
    def _dependency(user: User = Depends(get_current_user)) -> User:
        if not user.has_permission(permission):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"Your role doesn't have the '{permission.value}' permission.",
            )
        return user

    return _dependency
