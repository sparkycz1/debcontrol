"""CSRF protection for forms (double-submit cookie).

The app doesn't have login/sessions yet, so we can't build on those.
Pattern: a GET that renders a form sets (if missing) a random `csrftoken`
cookie, and the same value is embedded as a hidden form field. On POST,
both values must match — an attacker's cross-site page can neither read
nor set the user's cookie (SameSite=Strict, HttpOnly).

Usage in a router that renders a form:

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(request, "tpl.html", {"csrf_token": csrf_token, ...})
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response

The token must be in `context` BEFORE the template renders (`TemplateResponse`
renders the body immediately in its constructor) — that's why this is split
into "get the value" and "store it in a cookie" instead of one function
operating on an already-built response.
"""

from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import get_db

CSRF_COOKIE_NAME = "csrftoken"
CSRF_FORM_FIELD = "csrf_token"
_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 8


def get_or_create_csrf_token(request: Request) -> tuple[str, str | None]:
    """Return (token_for_template, value_for_new_cookie_or_None).

    The second element is `None` when the client already has a valid
    cookie — in that case it shouldn't be re-set (that would needlessly
    extend its lifetime). It's also `None` when `app.auth.middleware`
    already decided on a token for this same request (`request.state.csrf_token`,
    set before any route runs) — reusing that instead of minting a second,
    different one is what keeps a route's own token-in-the-form consistent
    with the one cookie the middleware will actually set on the response.
    """
    existing = request.cookies.get(CSRF_COOKIE_NAME)
    if existing:
        return existing, None
    already_provisioned = getattr(request.state, "csrf_token", None)
    if already_provisioned:
        return already_provisioned, None
    new_token = secrets.token_urlsafe(32)
    return new_token, new_token


def set_csrf_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        httponly=True,
        samesite="strict",
        secure=get_settings().is_production,
        max_age=_COOKIE_MAX_AGE_SECONDS,
    )


async def verify_csrf(request: Request, db: AsyncSession = Depends(get_db)) -> None:
    """FastAPI dependency — add to every state-changing (POST/PUT/DELETE) endpoint."""
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    form = await request.form()
    form_token = form.get(CSRF_FORM_FIELD)
    if (
        not cookie_token
        or not form_token
        or not secrets.compare_digest(str(form_token), cookie_token)
    ):
        # Imported lazily: app.audit -> app.db.session -> app.core.config
        # would otherwise be a real import-time cycle with app.core.csrf
        # (app.auth.middleware imports both this module and app.audit).
        from app.audit import log_event
        from app.db.models.audit_log import AuditOutcome

        await log_event(
            db,
            request=request,
            action="auth.csrf_rejected",
            summary=f"Blocked {request.method} {request.url.path}: missing or invalid CSRF token",
            outcome=AuditOutcome.DENIED,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token — reload the page and try again.",
        )
