"""FastAPI application entry point."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from fastapi.openapi.utils import get_openapi
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.auth.middleware import require_auth
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.proxy_headers import ProxyHeadersMiddleware
from app.core.version import APP_VERSION
from app.db.session import AsyncSessionLocal
from app.scheduling.builtin_actions import register_builtin_actions
from app.web.routes import (
    ai,
    api_docs,
    api_v1,
    api_v1_account,
    api_v1_audit,
    api_v1_checks,
    api_v1_dashboard,
    api_v1_notifications,
    api_v1_roles,
    api_v1_scheduling,
    api_v1_settings,
    api_v1_users,
    audit,
    auth,
    branding,
    checks,
    dashboard,
    fleet,
    impersonation,
    inform,
    live_ws,
    logs_ws,
    machine_groups,
    machines,
    maintenance,
    notifications,
    roles,
    scheduling,
    terminal_ws,
    theme,
    users,
)
from app.web.routes import settings as settings_routes

settings = get_settings()
configure_logging(settings.log_level)
# Populates app.scheduling.actions' registry — the "New scheduled task" form
# reads from it. Idempotent, and also called from app.scheduling.jobs (and
# again in each forked Celery worker child) so the worker processes have it
# too without needing to import this module.
register_builtin_actions()

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "web" / "static"

# Strict CSP: no inline scripts/styles, no external CDN (htmx and xterm.js
# are both vendored locally). `connect-src 'self'` is spelled out explicitly
# (rather than relying on `default-src 'self'`'s fallback) for the
# interactive terminal feature (`app/web/routes/terminal_ws.py`): a
# WebSocket connection is governed by `connect-src`, and per the CSP spec
# 'self' already matches the same-origin `ws`/`wss` upgrade of this page's
# own `http`/`https` origin — no broader scheme/host needed, so this adds
# nothing beyond what a same-origin WebSocket already requires.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


def _custom_openapi(app: FastAPI) -> dict[str, Any]:
    """Injects a `bearerAuth` security scheme into the generated OpenAPI
    schema, so Swagger UI (`GET /api`) shows an "Authorize" button and sends
    `Authorization: Bearer <token>` on every "Try it out" request under
    `/api/v1/...`.

    Deliberately not done via `Security(HTTPBearer())` added as a dependency
    on every one of `api_v1*.py`'s ~100 endpoints — `app.auth.dependencies.
    get_api_token_user` already reads the header itself and doesn't need
    FastAPI's own security dependency to function; this affects only what
    the schema *describes* and what Swagger UI sends, not how a request is
    actually authenticated.

    Cached on `app.openapi_schema` after the first call — the same caching
    FastAPI's own default `app.openapi()` method does, which this replaces.
    """
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "description": (
            "A per-user API token, created at /account (an admin must "
            "enable API access on the account first)."
        ),
    }
    for path, operations in schema.get("paths", {}).items():
        if not path.startswith("/api/v1/"):
            continue
        for operation in operations.values():
            if isinstance(operation, dict):
                operation["security"] = [{"bearerAuth": []}]

    app.openapi_schema = schema
    return schema


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    settings.ssh_data_dir.mkdir(parents=True, exist_ok=True)
    # One long-lived Redis connection pool for the *login rate limiter*
    # (app.auth.rate_limit) — nothing to do with the task queue, which is
    # Celery and talks to Redis from the worker processes on its own. Kept
    # here so a burst of login attempts doesn't open a fresh connection per
    # request.
    # redis-py's `from_url` carries no annotations, hence the ignore.
    app.state.redis = aioredis.from_url(settings.redis_url)  # type: ignore[no-untyped-call]
    # The auth middleware (app.auth.middleware) needs a DB session but runs
    # outside FastAPI's dependency injection — this is what it opens one
    # from. Kept on app.state (like `redis` above) rather than imported
    # directly so tests can point it at their own SQLite engine instead of
    # the real Postgres one `AsyncSessionLocal` is bound to.
    app.state.db_session_factory = AsyncSessionLocal
    try:
        yield
    finally:
        await app.state.redis.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="debcontrol",
        description="Manage Debian machines over SSH — see /api for interactive docs.",
        version=APP_VERSION,
        lifespan=lifespan,
        # The built-in Swagger UI at `docs_url` is replaced by a self-hosted
        # one at plain `/api` (app/web/routes/api_docs.py) — FastAPI's
        # default page pulls its JS/CSS from a CDN and inlines its own
        # init script, both of which this app's CSP forbids. `openapi_url`
        # is disabled here too (`None`) — `app/web/routes/api_docs.py`
        # defines its own `GET /openapi.json` instead, gated the same way
        # `GET /api` is (logged in AND `User.api_access_enabled`), since
        # FastAPI's own built-in route accepts no `Depends` to add that
        # check to.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.openapi = lambda: _custom_openapi(app)  # type: ignore[method-assign]

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Registered first so it ends up outermost (see the `_require_auth`
    # comment below for why registration order maps to layering here) —
    # every other middleware, and every route/WebSocket handler, needs to
    # see the corrected scheme, not just the ones that happen to run after
    # some other check. See app.core.proxy_headers's own module docstring
    # for what this fixes and why trusting it is safe.
    app.add_middleware(
        ProxyHeadersMiddleware,
        trust_all=settings.trust_all_proxies,
        trusted_networks=settings.trusted_proxy_networks,
        trust_forwarded_for=settings.trust_forwarded_for,
    )

    # Starlette's own session middleware — used *only* to carry OIDC's
    # `state`/`nonce` across the redirect to/from the provider (Authlib
    # reads/writes `request.session` itself). Unrelated to the app's own
    # login sessions (app.auth.sessions, a DB row + a separate cookie) —
    # this one is short-lived (only needs to survive one redirect round
    # trip) and never holds anything that grants access by itself.
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key.get_secret_value(),
        session_cookie="oidc_flow",
        same_site="lax",  # "strict" would drop this cookie on the provider's redirect back.
        https_only=settings.is_production,
        max_age=600,
    )

    # Registered before `security_headers` below so that middleware ends up
    # *outermost* (Starlette wraps middleware in reverse registration order)
    # — meaning it still gets to add CSP/etc. headers to a response
    # `require_auth` returns directly (a redirect to /login), not just to
    # ones that reached a route.
    @app.middleware("http")
    async def _require_auth(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        return await require_auth(request, call_next)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Severs `window.opener` for any cross-origin page this app opens
        # or is opened by (e.g. an OIDC provider's popup/redirect chain).
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

    app.include_router(api_docs.router)
    app.include_router(branding.router)
    app.include_router(auth.router)
    app.include_router(dashboard.router)
    app.include_router(fleet.router)
    app.include_router(checks.router)
    app.include_router(machines.router)
    app.include_router(machine_groups.router)
    app.include_router(scheduling.router)
    app.include_router(audit.router)
    app.include_router(ai.router)
    app.include_router(inform.router)
    app.include_router(api_v1.router)
    app.include_router(api_v1_scheduling.router)
    app.include_router(api_v1_users.router)
    app.include_router(api_v1_roles.router)
    app.include_router(api_v1_audit.router)
    app.include_router(api_v1_settings.router)
    app.include_router(api_v1_dashboard.router)
    app.include_router(api_v1_account.router)
    app.include_router(api_v1_checks.router)
    app.include_router(api_v1_notifications.router)
    app.include_router(users.router)
    app.include_router(impersonation.router)
    app.include_router(roles.router)
    app.include_router(maintenance.router)
    app.include_router(notifications.router)
    app.include_router(settings_routes.router)
    app.include_router(theme.router)
    # No HTTP dependency here — WebSocket connections never go through
    # `app.auth.middleware`, so this router does its own auth entirely
    # inside the handler. See terminal_ws.py's module docstring.
    app.include_router(terminal_ws.router)
    # Same no-HTTP-dependency reasoning as terminal_ws.router above — see
    # live_ws.py's own module docstring for what this one relays.
    app.include_router(live_ws.router)
    # Live log following (Logs tab) — authenticates like terminal_ws.
    app.include_router(logs_ws.router)

    @app.get("/", include_in_schema=False)
    async def root() -> Response:
        return RedirectResponse(url="/dashboard")

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
