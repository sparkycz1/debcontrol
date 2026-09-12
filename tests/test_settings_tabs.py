"""Settings' tab split (General / Checks & retention / Security /
Integrations / AI) — see app/web/routes/settings.py's module comment
above `_TABS`. Unlike the machine/group tabs, there's one GET route for
all five (`?tab=...`), so these tests focus on: each tab shows only its
own content, a POST handler redirects back to *its own* tab (not always
"General"), and an unknown tab value falls back cleanly instead of
404ing or rendering nothing.
"""

from __future__ import annotations

import re


def _tabnav_html(page_text: str) -> str:
    match = re.search(r'<nav class="tab-nav">.*?</nav>', page_text, re.DOTALL)
    assert match is not None, "no tab-nav found on the settings page"
    return match.group(0)


async def test_settings_tabs_show_the_same_five_tabs_everywhere(client):
    for tab in ("general", "checks", "security", "integrations", "ai"):
        response = await client.get(f"/settings?tab={tab}")
        assert response.status_code == 200, tab
        tabnav = _tabnav_html(response.text)
        for expected in (
            "/settings?tab=general",
            "/settings?tab=checks",
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


async def test_security_tab_has_audit_log_not_general_or_checks_content(client):
    response = await client.get("/settings?tab=security")
    assert response.status_code == 200
    assert "Audit log" in response.text
    assert "App SSH identity" not in response.text
    assert "Dashboard trends" not in response.text


async def test_checks_tab_has_background_checks_and_retention(client):
    response = await client.get("/settings?tab=checks")
    assert response.status_code == 200
    assert "Dashboard trends" in response.text
    assert "Update run history" in response.text
    assert "Monitoring history" in response.text
    assert 'name="ssh_connect_timeout"' in response.text
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


async def test_saving_audit_retention_redirects_back_to_checks_tab(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/audit-retention",
        data={"retention_days": "10", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=checks"


async def test_saving_background_checks_redirects_back_to_checks_tab(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/background-checks",
        data={
            "csrf_token": csrf_token,
            "ssh_connect_timeout": "15",
            "update_timeout_seconds": "900",
            "reachability_check_interval_seconds": "30",
            "facts_refresh_interval_seconds": "1800",
            "monitoring_interval_seconds": "60",
            "reachability_check_concurrency": "10",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=checks"

    page = await client.get("/settings?tab=checks")
    assert 'id="ssh_connect_timeout"' in page.text
    ssh_timeout_field = re.search(r'id="ssh_connect_timeout"[^>]*>', page.text)
    assert ssh_timeout_field is not None
    assert 'value="15"' in ssh_timeout_field.group(0)


async def test_background_checks_rejects_out_of_range_values(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/background-checks",
        data={
            "csrf_token": csrf_token,
            "ssh_connect_timeout": "9999",
            "update_timeout_seconds": "900",
            "reachability_check_interval_seconds": "30",
            "facts_refresh_interval_seconds": "1800",
            "monitoring_interval_seconds": "60",
            "reachability_check_concurrency": "10",
        },
    )
    assert response.status_code == 200
    assert "must be between" in response.text


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


async def test_saving_oidc_provider_name_persists(client, db_session_factory):
    from sqlalchemy import select

    from app.db.models.app_settings import AppSettings

    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/settings/oidc",
        data={
            "csrf_token": csrf_token,
            "oidc_provider_name": "Entra ID",
            "oidc_username_claim": "preferred_username",
            "oidc_scopes": "openid profile",
        },
        follow_redirects=False,
    )

    async with db_session_factory() as db:
        result = await db.execute(select(AppSettings))
        app_settings = result.scalar_one()
        assert app_settings.oidc_provider_name == "Entra ID"

    response = await client.get("/settings?tab=integrations")
    assert 'value="Entra ID"' in response.text


async def test_login_button_shows_the_configured_oidc_provider_name(
    anonymous_client, db_session_factory
):
    from app.db.models.app_settings import AppSettings

    async with db_session_factory() as db:
        db.add(
            AppSettings(
                oidc_enabled=True,
                oidc_provider_name="Entra ID",
                oidc_issuer_url="https://idp.example.com",
                oidc_client_id="client-id",
            )
        )
        await db.commit()

    response = await anonymous_client.get("/login")
    assert "Log in with Entra ID" in response.text
    assert "Log in with OIDC" not in response.text


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
