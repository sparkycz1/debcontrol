"""Interactive API documentation — Swagger UI, served at `GET /api`.

Deliberately **not** `fastapi.openapi.docs.get_swagger_ui_html()`: that
helper (a) points `swagger_js_url`/`swagger_css_url` at jsdelivr's CDN by
default, and (b) inlines Swagger UI's own initialization as a `<script>`
block directly in the HTML it returns. Both are incompatible with this
app's CSP (`script-src 'self'`, `style-src 'self'`, no CDN, no inline
scripts) — under a real browser enforcing that policy, the page would load
with an empty `<div id="swagger-ui">` and nothing else, exactly the class
of silent breakage this app's CSP has bitten before (see the terminal
page's fixed inline-`style` bug in `wiki/Architecture.md`).

Instead: `swagger-ui-dist` is vendored locally (same convention as htmx and
xterm.js — see `app/web/static/js/swagger-ui-bundle.js`,
`.../swagger-ui-standalone-preset.js` (the "StandaloneLayout" — the topbar
and overall page chrome — ships as a separate bundle from swagger-ui-bundle.js
itself, easy to miss since some examples online only load the one file) and
`.../css/swagger-ui.css`, all pinned to the same exact version, no CDN
reference at runtime), and this page is a plain Jinja template like every
other page in the app, with its own external init script
(`app/web/static/js/swagger-init.js`) instead of an inline one.

This route intentionally does **not** appear in `_PUBLIC_PATHS`/
`_PUBLIC_PREFIXES` in `app.auth.middleware` — `/api/` there is public only
because those routes authenticate themselves with a bearer token, not a
session. `/api` (this exact path, no trailing content) and `/openapi.json`
both fall outside that prefix, so both go through the normal session-login
check like any other page. That is deliberate: the OpenAPI schema is a
complete map of every endpoint, parameter, and permission this app has —
handing that to anyone with network access, logged in or not, would be a
reconnaissance gift. Once inside, "Authorize" in the UI takes one of this
account's own API tokens (see `/account`) for actually trying requests.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from app.web.templating import templates

router = APIRouter()


@router.get("/api", include_in_schema=False)
async def api_docs(request: Request) -> Response:
    return templates.TemplateResponse(request, "api_docs.html", {})
