"""The ASGI middleware that puts auth in front of every page.

Registered in `app.main` — see that module's comment on middleware
ordering for why it has to be registered *before* the security-headers
middleware (so CSP etc. still land on a redirect-to-login response, not
just on responses that reached a real route).

Two things happen on every request, public or not:

1. A CSRF token is ensured (`app.core.csrf`) and stashed on
   `request.state.csrf_token` — this lets `base.html` (and the login pages)
   render a token-carrying form without every route needing its own
   `get_or_create_csrf_token`/`set_csrf_cookie` dance just for that. Routes
   that already do that dance themselves (most of the pre-existing ones)
   are unaffected — they just read back the same cookie this already set.
2. Everything *not* on the public allowlist below requires a valid session
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

from collections.abc import Awaitable, Callable
from urllib.parse import quote

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse

from app.auth.sessions import SESSION_COOKIE_NAME, get_valid_session
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie
from app.db.models.user import AuthProvider, User

# Reachable with no session at all. Exact paths, plus two prefixes below.
_PUBLIC_PATHS = frozenset(
    {
        "/login",
        "/login/totp",
        "/logout",
        "/healthz",
        "/auth/oidc/login",
        "/auth/oidc/callback",
    }
)
# `/static/`: CSS/JS/the vendored htmx build — the login page needs these
# too. `/api/`: machine-to-machine endpoints (currently just self-registration)
# authenticated with their own bearer token, not a user session at all.
_PUBLIC_PREFIXES = ("/static/", "/api/")


# Reachable with a valid session even while a role's `require_totp` block is
# in effect — enrolling TOTP (GET renders the form, POST confirms it), the
# account page it's linked from, and logging out (a blocked user who won't
# or can't enroll right now must still be able to end their own session,
# not just be trapped on the enrollment page). Nothing else.
# See `_totp_enrollment_required` below.
_TOTP_ENROLL_ALLOWLIST = frozenset({"/account", "/account/totp/enroll", "/logout"})


def _is_public(path: str) -> bool:
    return path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES)


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


def _totp_enrollment_required(user: User) -> bool:
    """Does this session's user need to be blocked pending TOTP enrollment?

    Real-time, on every request — re-derived from the user's *current* role
    and *current* `totp_enabled` state (both freshly loaded with the session
    a moment ago), not cached from login. This is what makes toggling a
    role's `require_totp` on take effect immediately for already-logged-in
    users, unlike `User.must_change_password`, which only ever steers the
    post-login redirect in `app.web.routes.auth._finish_login` and is never
    re-checked afterwards.

    OIDC accounts are exempt: TOTP isn't offered for them at all (see
    `app.db.models.user`'s module docstring) — a role with `require_totp`
    assigned to an OIDC user would otherwise be an unconditional, permanent
    lockout, since there's no enrollment flow for them to complete. Their
    provider is expected to own MFA instead.
    """
    if not user.role.require_totp:
        return False
    if user.auth_provider == AuthProvider.OIDC:
        return False
    return not user.totp_enabled


async def require_auth(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    csrf_token, new_csrf_cookie = get_or_create_csrf_token(request)
    request.state.csrf_token = csrf_token

    if not _is_public(request.url.path):
        session = None
        raw_token = request.cookies.get(SESSION_COOKIE_NAME)
        if raw_token:
            db_session_factory = request.app.state.db_session_factory
            async with db_session_factory() as db:
                session = await get_valid_session(db, raw_token)

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

        if _totp_enrollment_required(session.user) and request.url.path not in (
            _TOTP_ENROLL_ALLOWLIST
        ):
            response = _redirect_to_totp_enroll(request)
            if new_csrf_cookie:
                set_csrf_cookie(response, new_csrf_cookie)
            return response

    response = await call_next(request)
    if new_csrf_cookie:
        set_csrf_cookie(response, new_csrf_cookie)
    return response
