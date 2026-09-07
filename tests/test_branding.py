"""Custom logo/favicon (`CUSTOM_LOGO`/`CUSTOM_FAVICON`) — app.web.branding's
URL-vs-local-path detection, and the GET /branding/logo|favicon routes that
serve a configured local path. The default (unset) case — the built-in
inline SVG icon + wordmark, static/img/favicon.svg — is covered by
test_web.py/test_auth.py's existing "does the page render" assertions
picking up base.html/login.html, which now include partials/_brand.html.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import Settings, get_settings
from app.web import branding


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _settings_with(**overrides: object) -> Settings:
    base = get_settings()
    return base.model_copy(update=overrides)


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com/logo.png",
        "https://example.com/logo.png",
        "data:image/png;base64,x",
    ],
)
def test_a_url_is_used_as_is(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    settings = _settings_with(custom_logo=value, custom_favicon=value)
    monkeypatch.setattr(branding, "get_settings", lambda: settings)
    assert branding.logo_src() == value
    assert branding.favicon_href() == value
    assert branding.custom_logo_path() is None
    assert branding.custom_favicon_path() is None


def test_a_bare_path_is_served_via_the_branding_route(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings_with(
        custom_logo="/mnt/branding/logo.svg", custom_favicon="/mnt/branding/favicon.ico"
    )
    monkeypatch.setattr(branding, "get_settings", lambda: settings)
    assert branding.logo_src() == "/branding/logo"
    assert branding.favicon_href() == "/branding/favicon"
    assert branding.custom_logo_path() == Path("/mnt/branding/logo.svg")
    assert branding.custom_favicon_path() == Path("/mnt/branding/favicon.ico")


def test_unset_is_none_for_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings_with(custom_logo=None, custom_favicon=None)
    monkeypatch.setattr(branding, "get_settings", lambda: settings)
    assert branding.logo_src() is None
    assert branding.favicon_href() is None
    assert branding.custom_logo_path() is None
    assert branding.custom_favicon_path() is None


async def test_branding_logo_route_serves_a_configured_local_file(
    monkeypatch, tmp_path, anonymous_client
):
    logo_file = tmp_path / "logo.svg"
    logo_file.write_text("<svg></svg>", encoding="utf-8")
    monkeypatch.setattr("app.web.routes.branding.custom_logo_path", lambda: logo_file)

    response = await anonymous_client.get("/branding/logo")

    assert response.status_code == 200
    assert response.text == "<svg></svg>"


async def test_branding_logo_route_404s_when_file_missing(monkeypatch, anonymous_client):
    monkeypatch.setattr("app.web.routes.branding.custom_logo_path", lambda: None)

    response = await anonymous_client.get("/branding/logo")

    assert response.status_code == 404


async def test_branding_favicon_route_falls_back_to_the_default_when_unset(
    monkeypatch, anonymous_client
):
    monkeypatch.setattr("app.web.routes.branding.custom_favicon_path", lambda: None)

    response = await anonymous_client.get("/branding/favicon", follow_redirects=False)

    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/static/img/favicon.svg"


async def test_branding_routes_are_reachable_without_a_session(anonymous_client):
    # No login required — the login page itself needs these to render its
    # own logo/favicon. A 404 (no custom file configured in tests) still
    # proves the route wasn't blocked by the auth middleware (that would be
    # a redirect to /login instead).
    response = await anonymous_client.get("/branding/logo", follow_redirects=False)
    assert response.status_code == 404
