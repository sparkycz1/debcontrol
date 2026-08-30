"""The light/dark theme toggle (POST /theme)."""

from __future__ import annotations


async def test_dashboard_defaults_to_dark_theme(client):
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert 'data-theme="dark"' in response.text


async def test_switching_to_light_sets_the_cookie_and_reflects_in_the_page(client):
    await client.get("/dashboard")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/theme",
        data={"theme": "light", "next": "/dashboard", "csrf_token": csrf_token},
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert client.cookies.get("theme") == "light"

    dashboard = await client.get("/dashboard")
    assert 'data-theme="light"' in dashboard.text
    # The header toggle now offers to switch back to dark.
    assert "Switch to dark theme" in dashboard.text


async def test_switching_back_to_dark(client):
    await client.get("/dashboard")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/theme", data={"theme": "light", "next": "/dashboard", "csrf_token": csrf_token}
    )
    await client.post(
        "/theme", data={"theme": "dark", "next": "/dashboard", "csrf_token": csrf_token}
    )
    assert client.cookies.get("theme") == "dark"


async def test_an_invalid_theme_value_falls_back_to_dark(client):
    await client.get("/dashboard")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/theme",
        data={"theme": "not-a-real-theme", "next": "/dashboard", "csrf_token": csrf_token},
    )
    assert client.cookies.get("theme") == "dark"


async def test_requires_csrf_token(client):
    await client.get("/dashboard")
    response = await client.post(
        "/theme", data={"theme": "light", "next": "/dashboard", "csrf_token": "wrong"}
    )
    assert response.status_code == 403


async def test_an_external_next_target_is_rejected(client):
    await client.get("/dashboard")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/theme",
        data={"theme": "light", "next": "//evil.example/phish", "csrf_token": csrf_token},
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


async def test_theme_route_requires_a_session(anonymous_client):
    response = await anonymous_client.post(
        "/theme", data={"theme": "light", "next": "/dashboard", "csrf_token": "anything"}
    )
    assert response.status_code in (303, 401)
