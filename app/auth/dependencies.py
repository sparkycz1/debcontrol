"""FastAPI dependencies for routes — `app.auth.middleware` already guarantees
every non-public request has a valid session and sets `request.state.user`
before a route ever runs; these just expose that typed, and enforce a
specific permission where a route needs more than "logged in"."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.api_tokens import get_valid_api_token
from app.db.models.role import Permission
from app.db.models.user import AuthProvider, User
from app.db.session import get_db


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


_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


async def get_api_token_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    """Like `get_current_user`, but for routes under `/api/` — those are on
    `app.auth.middleware`'s public-prefix allowlist (no session cookie), so
    they authenticate with a bearer API token instead (see
    `app.auth.api_tokens`). Used by the read-only REST API
    (`app.web.routes.api_v1`)."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token.")
    token = await get_valid_api_token(db, auth_header.removeprefix("Bearer ").strip())
    if token is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Invalid, expired, or revoked API token."
        )
    user = token.user
    # The token's own limits, on top of what the account may do.
    if token.read_only and request.method not in _READ_METHODS:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="This API token is read-only.",
        )
    # Read by `app.services.access_scope.allowed_group_ids` for the rest of
    # this request (the instance belongs to this request's session only).
    user.token_group_scope = token.group_scope
    # Same real-time `require_totp` gate `app.auth.middleware` applies to
    # session requests (see its `_totp_enrollment_required`), but an API
    # token has no interactive way to enroll TOTP — there's no browser flow
    # to redirect it into. A flat 403 telling the caller what to do (finish
    # enrollment via the web UI, using this same account/session) is the
    # only sensible option; OIDC accounts are exempt for the same reason
    # the session-side gate exempts them (no TOTP enrollment offered at all).
    if (
        user.role.require_totp
        and user.auth_provider != AuthProvider.OIDC
        and not user.totp_enabled
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(
                "This account's role requires two-factor authentication. Log in to the web "
                "UI and enroll TOTP (Account -> Two-factor authentication) before using the API."
            ),
        )
    # `app.auth.middleware` never sets `request.state.user` for `/api/`
    # requests (they're on its public-prefix allowlist, authenticated here
    # instead of by session cookie) — set it ourselves so `app.audit.
    # log_event`'s automatic actor resolution (`request.state.user`) works
    # the same way for an API-token request as it already does for a
    # cookie-session one, with no call site needing to pass `actor=`
    # explicitly just because the request came in over the API.
    request.state.user = user
    return user


def require_api_permission(permission: Permission) -> Callable[..., Awaitable[User]]:
    async def _dependency(user: User = Depends(get_api_token_user)) -> User:
        if not user.has_permission(permission):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"This API token's account lacks the '{permission.value}' permission.",
            )
        return user

    return _dependency
