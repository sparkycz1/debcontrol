"""Serves a locally-configured `CUSTOM_LOGO`/`CUSTOM_FAVICON` file (see
`app.web.branding`'s module docstring) — only reached when that setting
holds a filesystem path rather than a URL; a URL is used directly in
`src`/`href` and never touches this router at all.

Public (no session needed — added to `app.auth.middleware`'s
`_PUBLIC_PREFIXES`): the logo/favicon must render on the login page too,
before anyone has authenticated.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, RedirectResponse

from app.web.branding import custom_favicon_path, custom_logo_path

router = APIRouter(prefix="/branding", tags=["branding"])

_DEFAULT_FAVICON = "/static/img/favicon.svg"


def _serve(path: Path | None) -> FileResponse:
    """Shared logic for both routes below. A misconfigured `.env` (typo'd
    path, file not mounted) gets a plain 404 rather than crashing the page
    that requested it as an `<img>`/favicon — a missing image just doesn't
    render, same as any other broken image URL."""
    if path is None or not path.is_file():
        raise HTTPException(
            status_code=404, detail="No custom file configured, or it doesn't exist."
        )
    media_type, _encoding = mimetypes.guess_type(path.name)
    return FileResponse(path, media_type=media_type or "application/octet-stream")


@router.get("/logo")
async def branding_logo() -> FileResponse:
    return _serve(custom_logo_path())


@router.get("/favicon", response_model=None)
async def branding_favicon() -> FileResponse | RedirectResponse:
    path = custom_favicon_path()
    if path is None or not path.is_file():
        # Falls back to the built-in favicon rather than a broken tab icon
        # — CUSTOM_FAVICON only reaches this route at all when it's a local
        # path (a URL is used directly and never hits this router), so a
        # 404 here always means "misconfigured," not "intentionally unset."
        return RedirectResponse(_DEFAULT_FAVICON)
    return _serve(path)
