"""Custom logo/favicon support — `CUSTOM_LOGO`/`CUSTOM_FAVICON` in `.env`
(`Settings.custom_logo`/`custom_favicon`), each accepting either a URL
(used as-is: `http(s)://` or a `data:` URI) or a local filesystem path,
which this app reads and serves itself at `GET /branding/logo` /
`GET /branding/favicon` (see `app/web/routes/branding.py`) — the deployer
mounts it into the container (e.g. a Docker volume) rather than needing
it built into the image. Deliberately only those two URL schemes count
as "a reference, not a path": a local filesystem path is near-universally
absolute (starts with `/` on Linux, the only OS this app ships an image
for) and would otherwise collide with a bare-`/`-prefix heuristic.

Unset (the default for both) keeps the built-in icon+wordmark: an inline
`<svg>` in `partials/_brand.html` for the header/login page (so its
equalizer-slider color can follow the site's own light/dark theme via
`currentColor`, the same way every other icon in this app does — a static
image file can't do that), and `static/img/favicon.svg` for the browser
tab icon (browsers render favicons on their own chrome, not this app's
theme, so a fixed dark color there is the right call, same as any other
site's static favicon).
"""

from __future__ import annotations

from pathlib import Path

from app.core.config import get_settings


def _is_reference(value: str) -> bool:
    """True if `value` should be used as-is in `src`/`href` (a URL this
    app doesn't need to read itself); False if it's a local filesystem
    path this app should serve at its own route instead."""
    return value.startswith(("http://", "https://", "data:"))


def logo_src() -> str | None:
    """URL for the header/login-page logo's `<img src>`, or `None` for
    the built-in default (see `partials/_brand.html`)."""
    value = get_settings().custom_logo
    if not value:
        return None
    return value if _is_reference(value) else "/branding/logo"


def favicon_href() -> str | None:
    """URL for `<link rel="icon" href>`, or `None` for the built-in
    default (`static/img/favicon.svg`)."""
    value = get_settings().custom_favicon
    if not value:
        return None
    return value if _is_reference(value) else "/branding/favicon"


def custom_logo_path() -> Path | None:
    """The configured `CUSTOM_LOGO` as a local filesystem path — `None`
    when unset, or when it's a URL/reference `app/web/routes/branding.py`
    doesn't need to (and shouldn't) read itself."""
    value = get_settings().custom_logo
    if value and not _is_reference(value):
        return Path(value)
    return None


def custom_favicon_path() -> Path | None:
    """Same as `custom_logo_path`, for `CUSTOM_FAVICON`."""
    value = get_settings().custom_favicon
    if value and not _is_reference(value):
        return Path(value)
    return None
