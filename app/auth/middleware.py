"""The ASGI middleware that puts auth in front of every page.

Registered in `app.main` — see that module's comment on middleware
ordering for why it has to be registered *before* the security-headers
middleware (so CSP etc. still land on a redirect-to-login response, not
just on responses that reached a real route).

Three things happen on every request, public or not:

1. A CSRF token is ensured (`app.core.csrf`) and stashed on
   `request.state.csrf_token` — this lets `base.html` (and the login pages)
   render a token-carrying form without every route needing its own
   `get_or_create_csrf_token`/`set_csrf_cookie` dance just for that. Routes
   that already do that dance themselves (most of the pre-existing ones)
   are unaffected — they just read back the same cookie this already set.
2. `request.state.locale` is set to the default (English) — overwritten
   below with the session's own account's chosen language, if any — so
   every template can call `t(request, "some.key")` unconditionally,
   logged in or not. See `app.i18n`'s module docstring.
3. Everything *not* on the public allowlist below requires a valid session
   (`app.auth.sessions`); `request.state.user`/`request.state.session` are
   set from it for the rest of the request. A missing/expired/revoked
   session redirects to `/login?next=<path>`.

This opens its own DB session via `request.app.state.db_session_factory`
rather than FastAPI's `Depends(get_db)` — middleware runs outside the
dependency-injection system. Same reasoning `app/tasks/jobs.py` already
uses `AsyncSessionLocal` directly for background jobs; the factory is on
`app.state` (see `app.main`'s `lifespan`) rather than imported directly so
tests can point it at their own SQLite engine (see `tests/conftest.py`).
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from urllib.parse import quote

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import client_ip
from app.auth import session_policy
from app.auth.sessions import SESSION_COOKIE_NAME, get_valid_session
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie
from app.db.models.user import AuthProvider, User
from app.db.models.webauthn_credential import WebAuthnCredential
from app.i18n import get_locale

# Reachable with no session at all. Exact paths, plus two prefixes below.
_PUBLIC_PATHS = frozenset(
    {
        "/login",
        "/login/password",
        "/login/totp",
        "/login/webauthn/options",
        "/login/webauthn/verify",
        "/logout",
        "/healthz",
        "/auth/oidc/login",
        "/auth/oidc/callback",
    }
)
# `/static/`: CSS/JS/the vendored htmx build — the login page needs these
# too. `/api/`: machine-to-machine endpoints (currently just self-registration)
# authenticated with their own bearer token, not a user session at all.
# `/branding/`: a deployer's custom logo/favicon (app.web.routes.branding) —
# same reasoning as `/static/`, the login page needs these too.
_PUBLIC_PREFIXES = ("/static/", "/api/", "/branding/")


# Reachable with a valid session even while a role's `require_totp` block is
# in effect — enrolling TOTP (GET renders the form, POST confirms it),
# registering a passkey instead (same enrollment requirement, satisfied
# either way — see `_totp_enrollment_required`), the account page it's all
# linked from, and logging out (a blocked user who won't or can't enroll
# right now must still be able to end their own session, not just be
# trapped on the enrollment page). Nothing else.
_TOTP_ENROLL_ALLOWLIST = frozenset(
    {
        "/account",
        "/account/totp/enroll",
        "/account/webauthn/register/options",
        "/account/webauthn/register/verify",
        "/logout",
    }
)


def _is_public(path: str) -> bool:
    return path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES)


# Outside Settings -> Security's network allowlist: assets the block page
# itself needs, the container health check, and machine self-registration
# (machine-to-machine, token-authenticated, typically from networks an
# operator never signs in from).
_NETWORK_EXEMPT_PATHS = frozenset({"/healthz", "/api/inform"})
_NETWORK_EXEMPT_PREFIXES = ("/static/", "/branding/")


async def _network_allowed(request: Request) -> bool:
    path = request.url.path
    if path in _NETWORK_EXEMPT_PATHS or path.startswith(_NETWORK_EXEMPT_PREFIXES):
        return True
    policy = session_policy.fresh_cached_policy()
    if policy is None:
        async with request.app.state.db_session_factory() as db:
            policy = await session_policy.load_policy(db)
    return policy.allows_ip(client_ip(request))


def _redirect_to_login(request: Request) -> Response:
    next_path = request.url.path
    if request.url.query:
        next_path += f"?{request.url.query}"
    login_url = f"/login?next={quote(next_path, safe='')}"
    if request.headers.get("HX-Request") == "true":
        # A plain redirect response to an htmx-driven request gets its HTML
        # swapped into whatever element made the request, not navigated —
        # same reasoning as machines.py's trust_host_key. HX-Redirect tells
        # htmx to navigate the whole page instead.
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": login_url})
    return RedirectResponse(url=login_url, status_code=status.HTTP_303_SEE_OTHER)


def _redirect_to_totp_enroll(request: Request) -> Response:
    enroll_url = "/account/totp/enroll"
    if request.headers.get("HX-Request") == "true":
        # Same reasoning as `_redirect_to_login` above.
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": enroll_url})
    return RedirectResponse(url=enroll_url, status_code=status.HTTP_303_SEE_OTHER)


def _needs_second_factor_check(user: User) -> bool:
    """Cheap, in-memory pre-check deciding whether `require_auth` needs to
    spend a query on `_has_webauthn_credential` at all — true only when
    every other `_totp_enrollment_required` condition below would already
    be satisfied without it. Keeps that extra query off the common case
    (a role with no `require_totp`, or an account that already has TOTP
    enabled) instead of running it on every authenticated request."""
    return (
        user.role.require_totp
        and user.auth_provider != AuthProvider.OIDC
        and not user.totp_enabled
    )


def _totp_enrollment_required(user: User, *, has_webauthn_credential: bool) -> bool:
    """Does this session's user need to be blocked pending a second-factor
    enrollment — TOTP, or at least one registered passkey (see
    `app.auth.webauthn`)?

    Real-time, on every request — re-derived from the user's *current* role
    and *current* `totp_enabled`/passkey state (all freshly loaded with the
    session a moment ago), not cached from login. This is what makes
    toggling a role's `require_totp` on take effect immediately for
    already-logged-in users, unlike `User.must_change_password`, which only
    ever steers the post-login redirect in
    `app.web.routes.auth._finish_login` and is never re-checked afterwards.

    OIDC accounts are exempt: neither TOTP nor passkey registration is
    offered for them here (see `app.db.models.user`'s module docstring) —
    a role with `require_totp` assigned to an OIDC user would otherwise be
    an unconditional, permanent lockout, since there's no enrollment flow
    for them to complete. Their provider is expected to own MFA instead.
    """
    if not user.role.require_totp:
        return False
    if user.auth_provider == AuthProvider.OIDC:
        return False
    return not user.totp_enabled and not has_webauthn_credential


async def _has_webauthn_credential(db: AsyncSession, user_id: uuid.UUID) -> bool:
    """Whether `user_id` has at least one registered passkey — only ever
    queried when `_needs_second_factor_check` says the answer could change
    `_totp_enrollment_required`'s outcome, so this stays off the hot path
    for accounts that already have TOTP enabled or a role that doesn't
    require a second factor at all."""
    result = await db.execute(
        select(func.count()).select_from(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user_id
        )
    )
    return (result.scalar_one() or 0) > 0


async def require_auth(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    csrf_token, new_csrf_cookie = get_or_create_csrf_token(request)
    request.state.csrf_token = csrf_token
    # Default for every request, including the login page and every other
    # public/anonymous one — there's no account yet to have a preference.
    # Overwritten below once a session resolves to one that has chosen a
    # non-default language. `Settings.default_locale` (DEFAULT_LANGUAGE)
    # is the deploy-wide starting point; see app.i18n's module docstring.
    request.state.locale = get_locale(None, default=get_settings().default_locale)

    if not await _network_allowed(request):
        # Before any session lookup or login form: from outside the allowed
        # networks there is nothing to sign in to. Same message for every
        # path, so it reveals nothing beyond "not from here".
        blocked: Response
        if request.url.path.startswith("/api/") or request.headers.get(
            "accept", ""
        ).startswith("application/json"):
            blocked = JSONResponse(
                {"detail": "Access from this network is not allowed."},
                status_code=status.HTTP_403_FORBIDDEN,
            )
        else:
            blocked = Response(
                "Access to debcontrol from this network is not allowed.",
                status_code=status.HTTP_403_FORBIDDEN,
                media_type="text/plain; charset=utf-8",
            )
        return blocked

    if not _is_public(request.url.path):
        session = None
        has_webauthn_credential = False
        raw_token = request.cookies.get(SESSION_COOKIE_NAME)
        if raw_token:
            db_session_factory = request.app.state.db_session_factory
            async with db_session_factory() as db:
                session = await get_valid_session(db, raw_token)
                if session is not None and _needs_second_factor_check(session.user):
                    has_webauthn_credential = await _has_webauthn_credential(
                        db, session.user.id
                    )

        if session is None:
            if request.headers.get("accept", "").startswith("application/json"):
                response: Response = JSONResponse(
                    {"detail": "Not authenticated."}, status_code=status.HTTP_401_UNAUTHORIZED
                )
            else:
                response = _redirect_to_login(request)
            if new_csrf_cookie:
                set_csrf_cookie(response, new_csrf_cookie)
            return response

        request.state.user = session.user
        request.state.session = session
        request.state.impersonator = session.impersonator
        request.state.locale = get_locale(
            session.user.locale, default=get_settings().default_locale
        )

        if _totp_enrollment_required(
            session.user, has_webauthn_credential=has_webauthn_credential
        ) and request.url.path not in (_TOTP_ENROLL_ALLOWLIST):
            response = _redirect_to_totp_enroll(request)
            if new_csrf_cookie:
                set_csrf_cookie(response, new_csrf_cookie)
            return response

    response = await call_next(request)
    if new_csrf_cookie:
        set_csrf_cookie(response, new_csrf_cookie)
    return response
