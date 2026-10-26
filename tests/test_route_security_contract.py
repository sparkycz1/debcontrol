"""The security contract every route of the app keeps, checked over the
whole route table at once, so a new route that forgets one fails here
instead of shipping:

- every web route that changes something (POST/PUT/PATCH/DELETE) checks
  the CSRF token (`app.core.csrf.verify_csrf`);
- every `/api/...` route authenticates its caller itself — `/api/` is a
  public prefix for the session middleware (`app.auth.middleware`), so a
  route there without its own token check would be open to anyone;
- every other web route depends on a permission (or at least on the
  signed-in user), not only on the middleware's "has a session".

Each exception is listed below with its reason. A new one belongs there
only with the same kind of reason, never just to get the test green.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

from fastapi.routing import APIRoute

from app.auth.dependencies import get_api_token_user, get_current_user
from app.core.csrf import verify_csrf
from app.main import app

_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Changes something but has no CSRF token, because no browser form calls it:
# the secret token in the address is the credential.
_NO_CSRF = {
    "/push/{token}": "push-check heartbeat from scripts (app/web/routes/check_push.py)",
    "/hooks/docker/{token}": "Git host webhook (app/web/routes/docker_hooks.py)",
    "/notifications/maintenance{rest:path}": "308 redirect only; the target checks CSRF",
}

# Under /api/ but not authenticated with an API token.
_API_OWN_AUTH = {
    "/api/inform": "machine self-registration, checked against INFORM_TOKEN",
}

# Web routes outside the public paths with no permission dependency: the
# session middleware still requires a signed-in user for each of them.
_SESSION_ONLY = {
    "/": "the dashboard; every panel on it fetches its data with a permission",
    "/theme": "the signed-in user's own light/dark choice",
    "/notifications/maintenance{rest:path}": "308 redirect to /scheduling/maintenance",
}

# Reachable without a session (app.auth.middleware's public paths) — each
# authenticates in its own way or shows nothing private.
_PUBLIC_PREFIXES = (
    "/login",
    "/logout",
    "/auth/oidc/",
    "/healthz",
    "/static",
    "/branding/",
    "/status/",
    "/push/",
    "/hooks/docker/",
)


def _routes(routes: Any) -> Iterator[APIRoute]:
    for route in routes:
        # FastAPI keeps an included router as one entry pointing at it.
        original = getattr(route, "original_router", None)
        if original is not None:
            yield from _routes(original.routes)
        elif isinstance(route, APIRoute):
            yield route


def _calls(dependant: Any) -> list[Callable[..., Any]]:
    out: list[Callable[..., Any]] = []
    for dep in dependant.dependencies:
        out.append(dep.call)
        out.extend(_calls(dep))
    return out


def _names(calls: list[Callable[..., Any]]) -> set[str]:
    return {getattr(call, "__qualname__", repr(call)) for call in calls}


def _all_routes() -> list[APIRoute]:
    routes = list(_routes(app.routes))
    # The walk itself must work — an empty table would pass every check.
    assert len(routes) > 300
    return routes


def test_every_mutating_web_route_checks_csrf() -> None:
    missing = sorted(
        route.path
        for route in _all_routes()
        if not route.path.startswith("/api/")
        and (route.methods or set()) & _MUTATING
        and verify_csrf not in _calls(route.dependant)
        and route.path not in _NO_CSRF
    )
    assert missing == []


def test_every_api_route_authenticates_its_caller() -> None:
    missing = []
    for route in _all_routes():
        if not route.path.startswith("/api/") or route.path in _API_OWN_AUTH:
            continue
        calls = _calls(route.dependant)
        if get_api_token_user not in calls and not any(
            "require_api_permission" in name for name in _names(calls)
        ):
            missing.append(route.path)
    assert missing == []


def test_every_private_web_route_needs_a_permission() -> None:
    missing = []
    for route in _all_routes():
        path = route.path
        if path.startswith(("/api/", *_PUBLIC_PREFIXES)) or path in _SESSION_ONLY:
            continue
        calls = _calls(route.dependant)
        if get_current_user not in calls and not any(
            "require_permission" in name for name in _names(calls)
        ):
            missing.append(path)
    assert missing == []


def test_the_exceptions_still_exist() -> None:
    """An exception left behind for a route that's gone would quietly
    excuse the next route given that path."""
    paths = {route.path for route in _all_routes()}
    for listed in (_NO_CSRF, _API_OWN_AUTH, _SESSION_ONLY):
        assert set(listed) <= paths
