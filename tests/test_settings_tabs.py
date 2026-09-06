"""Settings' tab split (General / Security / Integrations / AI) — see
app/web/routes/settings.py's module comment above `_TABS`. Unlike the
machine/group tabs, there's one GET route for all four (`?tab=...`), so
these tests focus on: each tab shows only its own content, a POST handler
redirects back to *its own* tab (not always "General"), and an unknown tab
value falls back cleanly instead of 404ing or rendering nothing.
"""

from __future__ import annotations

import re


def _tabnav_html(page_text: str) -> str:
    match = re.search(r'<nav class="tab-nav">.*?</nav>', page_text, re.DOTALL)
    assert match is not None, "no tab-nav found on the settings page"
    return match.group(0)


async def test_settings_tabs_show_the_same_four_tabs_everywhere(client):
    for tab in ("general", "security", "integrations", "ai"):
        response = await client.get(f"/settings?tab={tab}")
        assert response.status_code == 200, tab
        tabnav = _tabnav_html(response.text)
        for expected in (
            "/settings?tab=general",
            "/settings?tab=security",
            "/settings?tab=integrations",
            "/settings?tab=ai",
        ):
            assert f'href="{expected}"' in tabnav
        assert tabnav.count('class="active" aria-current="page"') == 1


async def test_default_tab_is_general(client):
    response = await client.get("/settings")
    assert response.status_code == 200
    assert "App SSH identity" in response.text
    assert "LDAP login" not in response.text
    assert "AI assistant" not in response.text


async def test_unknown_tab_falls_back_to_general(client):
    response = await client.get("/settings?tab=not-a-real-tab")
    assert response.status_code == 200
    assert "App SSH identity" in response.text


async def test_security_tab_has_audit_and_dashboard_trends_not_general_content(client):
    response = await client.get("/settings?tab=security")
    assert response.status_code == 200
    assert "Audit log" in response.text
    assert "Dashboard trends" in response.text
    assert "App SSH identity" not in response.text


async def test_integrations_tab_has_syslog_ldap_and_oidc(client):
    response = await client.get("/settings?tab=integrations")
    assert response.status_code == 200
    assert "Syslog forwarding" in response.text
    assert "LDAP login" in response.text
    assert "OIDC login" in response.text
    assert "AI assistant" not in response.text
    # On (verified) by default — an unchecked box would silently disable
    # certificate verification, the opposite of the safe default.
    assert 'name="ldap_tls_verify" checked' in response.text


async def test_ai_tab_has_ai_assistant_content(client):
    response = await client.get("/settings?tab=ai")
    assert response.status_code == 200
    assert "AI assistant" in response.text
    assert "Token limits" in response.text
    assert "LDAP login" not in response.text


async def test_saving_audit_retention_redirects_back_to_security_tab(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/audit-retention",
        data={"retention_days": "10", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=security"


async def test_saving_ldap_settings_redirects_back_to_integrations_tab(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/ldap",
        data={"csrf_token": csrf_token, "ldap_enabled": ""},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=integrations"


async def test_disabling_ldap_tls_verify_persists(client, db_session_factory):
    from sqlalchemy import select

    from app.db.models.app_settings import AppSettings

    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/settings/ldap",
        data={"csrf_token": csrf_token, "ldap_enabled": ""},  # ldap_tls_verify omitted = unchecked
        follow_redirects=False,
    )

    async with db_session_factory() as db:
        result = await db.execute(select(AppSettings))
        app_settings = result.scalar_one()
        assert app_settings.ldap_tls_verify is False

    response = await client.get("/settings?tab=integrations")
    assert 'name="ldap_tls_verify" checked' not in response.text


async def test_saving_ai_limits_redirects_back_to_ai_tab(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/ai-limits",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=ai"


async def test_generating_ssh_key_redirects_back_to_general_tab(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/ssh-key/generate",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=general"
