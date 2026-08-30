"""The light/dark theme toggle in the page header.

A pure UI preference stored client-side in a cookie — no DB row, no
per-user setting, nothing to migrate. `base.html` reads the cookie and
sets `data-theme` on `<html>`; `app/web/static/css/style.css` defines the
light palette under `:root[data-theme="light"]` and dark (the default for
a first-time visit with no cookie yet) under plain `:root`.

Requires a session like every other page (this router isn't on
`app.auth.middleware`'s public allowlist) — the toggle only appears in the
logged-in header, and the unauthenticated login page always renders dark.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form
from fastapi.responses import RedirectResponse

from app.core.config import get_settings
from app.core.csrf import verify_csrf

router = APIRouter()

THEME_COOKIE_NAME = "theme"
_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365
_VALID_THEMES = ("light", "dark")


def _safe_redirect_target(next_path: str) -> str:
    """Only ever redirect to a same-origin relative path — `next_path`
    comes from a form field an attacker could tamper with, so an absolute
    or protocol-relative ("//evil.example") value is rejected in favor of
    a safe default, the same way `app.auth.middleware`'s `next=` handling
    already treats it as untrusted input."""
    if next_path.startswith("/") and not next_path.startswith("//"):
        return next_path
    return "/dashboard"


@router.post("/theme", dependencies=[Depends(verify_csrf)])
async def set_theme(theme: str = Form(...), next: str = Form("/dashboard")) -> RedirectResponse:
    chosen = theme if theme in _VALID_THEMES else "dark"
    response = RedirectResponse(
        url=_safe_redirect_target(next), status_code=303
    )
    response.set_cookie(
        THEME_COOKIE_NAME,
        chosen,
        max_age=_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=get_settings().is_production,
    )
    return response
