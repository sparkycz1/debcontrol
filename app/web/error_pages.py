"""HTML error pages for the web UI.

FastAPI's default `HTTPException` handler answers every 403/404 with a bare
`{"detail": "..."}` JSON body — right for the REST API and for htmx
fragment requests (whose callers handle the status themselves), but a
browser landing on a mistyped or stale URL got a raw JSON blob instead of
a page with the app's navigation. This handler renders `error.html` for
exactly that case and defers to FastAPI's own handler for everything else.
"""

from __future__ import annotations

from fastapi import Request, Response
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.web.templating import templates

# Statuses that get a page of their own; anything else keeps the default.
_HTML_STATUSES = frozenset({403, 404})


def _wants_html_page(request: Request) -> bool:
    if request.method != "GET":
        return False
    if request.url.path.startswith("/api/") or request.url.path == "/openapi.json":
        return False
    if request.headers.get("hx-request"):
        return False
    # base.html renders the navigation from the signed-in account, so a
    # page needs one — an anonymous request never reaches a route anyway
    # (the auth middleware redirects it to /login first).
    if getattr(request.state, "user", None) is None:
        return False
    return "text/html" in request.headers.get("accept", "")


async def html_http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> Response:
    if exc.status_code not in _HTML_STATUSES or not _wants_html_page(request):
        return await http_exception_handler(request, exc)
    return templates.TemplateResponse(
        request,
        "error.html",
        {"status_code": exc.status_code},
        status_code=exc.status_code,
        headers=getattr(exc, "headers", None),
    )
