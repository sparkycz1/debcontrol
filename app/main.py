"""FastAPI application entry point."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from arq import create_pool
from arq.connections import RedisSettings
from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.scheduling.builtin_actions import register_builtin_actions
from app.web.routes import audit, inform, machine_groups, machines, scheduling, users
from app.web.routes import settings as settings_routes

settings = get_settings()
configure_logging(settings.log_level)
# Populates app.scheduling.actions' registry — the "New scheduled task" form
# reads from it. Idempotent, and also called from app.tasks.worker so the
# worker process has it too without needing to import this module.
register_builtin_actions()

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "web" / "static"

# Strict CSP: no inline scripts/styles, no external CDN (htmx is vendored locally).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    settings.ssh_data_dir.mkdir(parents=True, exist_ok=True)
    app.state.arq_redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        yield
    finally:
        await app.state.arq_redis.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="debcontrol",
        lifespan=lifespan,
        # Don't expose interactive API docs publicly in production.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

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
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

    app.include_router(machines.router)
    app.include_router(machine_groups.router)
    app.include_router(scheduling.router)
    app.include_router(audit.router)
    app.include_router(inform.router)
    app.include_router(users.router)
    app.include_router(settings_routes.router)

    @app.get("/", include_in_schema=False)
    async def root() -> Response:
        return RedirectResponse(url="/machines")

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
