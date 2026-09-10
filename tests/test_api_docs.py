from __future__ import annotations

from app.db.models.role import Permission


async def test_api_docs_page_requires_login(anonymous_client):
    response = await anonymous_client.get("/api", follow_redirects=False)
    assert response.status_code in (302, 303, 307)
    assert response.headers["location"].startswith("/login")


async def test_openapi_schema_requires_login(anonymous_client):
    response = await anonymous_client.get("/openapi.json", follow_redirects=False)
    assert response.status_code in (302, 303, 307)
    assert response.headers["location"].startswith("/login")


async def test_api_docs_page_renders_for_a_logged_in_user(client):
    response = await client.get("/api")
    assert response.status_code == 200
    assert 'id="swagger-ui"' in response.text
    assert 'data-openapi-url="/openapi.json"' in response.text
    # Self-hosted assets only — no CDN reference, per this app's CSP.
    assert "cdn.jsdelivr.net" not in response.text
    assert "/static/js/swagger-ui-bundle.js" in response.text
    assert "/static/js/swagger-ui-standalone-preset.js" in response.text
    assert "/static/css/swagger-ui.css" in response.text


async def test_api_docs_page_requires_api_access_enabled(client, login_as):
    await login_as(client, permissions=set(Permission))  # every permission, but no API access
    response = await client.get("/api")
    assert response.status_code == 403


async def test_openapi_schema_requires_api_access_enabled(client, login_as):
    await login_as(client, permissions=set(Permission))
    response = await client.get("/openapi.json")
    assert response.status_code == 403


async def test_openapi_schema_documents_bearer_auth_for_the_rest_api(client):
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()

    assert schema["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"

    machines_get = schema["paths"]["/api/v1/machines"]["get"]
    assert machines_get["security"] == [{"bearerAuth": []}]

    # Web-only routes (session-cookie auth, not the REST API) shouldn't be
    # tagged with the API's bearer scheme.
    dashboard_get = schema["paths"]["/dashboard"]["get"]
    assert "security" not in dashboard_get
