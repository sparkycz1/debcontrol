"""app/i18n (locale discovery, translate() fallback rules) and the
self-service language switcher — `POST /account/locale` (web) and
`POST /api/v1/account/locale` / `GET /api/v1/locales` (REST).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import i18n
from tests.test_api_v1_extended import _api_token


@pytest.fixture(autouse=True)
def _fresh_registry():
    """`i18n._registry()` is `@lru_cache`d (parsed once per process) — clear
    it before and after every test in this file so a test that points
    `LOCALES_DIR` at a temporary directory never leaks its fake registry
    into an unrelated test, and a real-file test always re-reads the
    shipped locale files rather than a stale cached copy from an earlier
    test run in the same session."""
    i18n._registry.cache_clear()
    yield
    i18n._registry.cache_clear()


def test_shipped_locales_include_english_and_czech():
    codes = {locale.code for locale in i18n.available_locales()}
    assert "en" in codes
    assert "cs" in codes


def test_available_locales_lists_english_first():
    locales = i18n.available_locales()
    assert locales[0].code == "en"


def test_get_locale_falls_back_to_default_for_unknown_or_none_code():
    default = i18n.get_locale(None)
    assert default.code == "en"
    assert i18n.get_locale("some-locale-nobody-shipped").code == "en"


def test_get_locale_returns_the_requested_one_when_it_exists():
    assert i18n.get_locale("cs").code == "cs"


def test_translate_uses_the_requested_locale():
    cs = i18n.get_locale("cs")
    assert i18n.translate(cs, "nav.dashboard") == "Přehled"


def test_translate_falls_back_to_english_for_a_key_missing_in_a_locale():
    # A locale file need not translate every key — see the module
    # docstring's "still catching up" reasoning.
    partial = i18n.Locale(code="xx", label="Test", strings={})
    en = i18n.get_locale(None)
    assert i18n.translate(partial, "nav.dashboard") == en.strings["nav.dashboard"]


def test_translate_falls_back_to_the_raw_key_when_nowhere_has_it():
    en = i18n.get_locale(None)
    assert i18n.translate(en, "no.such.key.anywhere") == "no.such.key.anywhere"


def test_translate_substitutes_kwargs():
    locale = i18n.Locale(code="xx", label="Test", strings={"greeting": "Hello, {name}!"})
    assert i18n.translate(locale, "greeting", name="Ada") == "Hello, Ada!"


def test_translate_a_missing_placeholder_returns_the_template_unsubstituted():
    locale = i18n.Locale(code="xx", label="Test", strings={"greeting": "Hello, {name}!"})
    assert i18n.translate(locale, "greeting") == "Hello, {name}!"


def test_malformed_locale_file_is_skipped_not_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "en.json").write_text(
        json.dumps({"meta": {"code": "en", "label": "English"}, "strings": {"a": "A"}}),
        encoding="utf-8",
    )
    (tmp_path / "broken.json").write_text("not json at all", encoding="utf-8")
    # meta.code doesn't match the filename — must be rejected, not silently
    # registered under the wrong code.
    (tmp_path / "de.json").write_text(
        json.dumps({"meta": {"code": "fr", "label": "Français"}, "strings": {}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(i18n, "LOCALES_DIR", tmp_path)

    locales = i18n.available_locales()

    assert {locale.code for locale in locales} == {"en"}


async def test_account_page_offers_a_language_picker(client):
    response = await client.get("/account")
    assert response.status_code == 200
    assert 'name="locale"' in response.text
    assert "Čeština" in response.text


async def test_switching_locale_translates_the_nav_bar(client):
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/account/locale", data={"locale": "cs", "csrf_token": csrf_token}
    )
    assert response.status_code == 303

    dashboard = await client.get("/dashboard")
    assert "Přehled" in dashboard.text
    assert 'lang="cs"' in dashboard.text


async def test_default_locale_is_english_for_a_user_who_never_chose_one(client):
    response = await client.get("/dashboard")
    assert "Dashboard" in response.text
    assert 'lang="en"' in response.text


async def test_machines_list_translates_into_czech(client):
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    await client.post("/account/locale", data={"locale": "cs", "csrf_token": csrf_token})

    response = await client.get("/machines")

    assert "Zařízení" in response.text
    assert "Přidat zařízení" in response.text
    assert "Tabulka" in response.text and "Seznam" in response.text and "Karty" in response.text


async def test_machines_empty_search_message_translates_and_keeps_literal_quotes(client):
    """A regression test for a real bug: the translation string's own
    literal quote marks around `{query}` were getting HTML-entity-escaped
    (`&#34;`) by Jinja's autoescape once the whole "No machines match ..."
    sentence came from one `t()` call instead of only the interpolated
    value — see the `| safe` comment in machines/list.html."""
    response = await client.get("/machines?q=zzz-nonexistent-zzz")

    assert 'No machines match "zzz-nonexistent-zzz".' in response.text
    assert "&#34;" not in response.text

    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    await client.post("/account/locale", data={"locale": "cs", "csrf_token": csrf_token})

    cs_response = await client.get("/machines?q=zzz-nonexistent-zzz")
    assert 'Žádná zařízení neodpovídají "zzz-nonexistent-zzz".' in cs_response.text
    assert "&#34;" not in cs_response.text


async def test_switching_to_an_unknown_locale_falls_back_to_english(client):
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/account/locale", data={"locale": "not-a-real-locale", "csrf_token": csrf_token}
    )
    assert response.status_code == 303

    dashboard = await client.get("/dashboard")
    assert 'lang="en"' in dashboard.text


async def test_anonymous_login_page_always_renders_in_english(anonymous_client):
    response = await anonymous_client.get("/login")
    assert response.status_code == 200
    assert 'lang="en"' in response.text
    assert "Log in" in response.text


async def test_locales_api_lists_english_and_czech(client):
    headers = await _api_token(client)
    response = await client.get("/api/v1/locales", headers=headers)
    assert response.status_code == 200
    codes = {row["code"] for row in response.json()}
    assert {"en", "cs"} <= codes


async def test_account_locale_api_round_trip(client):
    headers = await _api_token(client)

    get_resp = await client.get("/api/v1/account", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["locale"] == "en"

    set_resp = await client.post(
        "/api/v1/account/locale", json={"locale": "cs"}, headers=headers
    )
    assert set_resp.status_code == 200
    assert set_resp.json()["locale"] == "cs"

    get_after = await client.get("/api/v1/account", headers=headers)
    assert get_after.json()["locale"] == "cs"
