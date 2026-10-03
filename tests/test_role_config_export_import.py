"""Export/import of role configuration — see `app/services/role_config.py`
for the design (conflict-handling policy) and `app/web/routes/roles.py` /
`app/web/routes/api_v1_roles.py` for the web/API routes.
"""

from __future__ import annotations

import json
import re

from httpx2 import AsyncClient


async def _api_token(client: AsyncClient) -> dict[str, str]:
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "role-config-test", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None
    return {"Authorization": f"Bearer {match.group(1)}"}


async def _create_role(client: AsyncClient, csrf_token: str, **overrides: object) -> None:
    data: dict[str, object] = {
        "name": "exported-role",
        "description": "a role",
        "permissions": ["machine.view"],
        "csrf_token": csrf_token,
    }
    data.update(overrides)
    response = await client.post("/roles", data=data)
    assert response.status_code == 303


async def test_export_includes_permissions(client):
    await client.get("/roles/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_role(
        client, csrf_token, name="exp-role", permissions=["machine.view", "machine.manage"]
    )

    response = await client.get("/roles/config/export")
    assert response.status_code == 200
    data = response.json()
    role = next(r for r in data["roles"] if r["name"] == "exp-role")
    assert set(role["permissions"]) == {"machine.view", "machine.manage"}


async def test_import_creates_role(client):
    await client.get("/roles/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload = {
        "roles": [
            {
                "name": "imported-role",
                "description": "restored",
                "require_totp": False,
                "permissions": ["machine.view", "scheduling.view"],
            }
        ]
    }
    response = await client.post(
        "/roles/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Created 1 role." in response.text

    roles_page = await client.get("/roles")
    assert "imported-role" in roles_page.text


async def test_import_skips_existing_role_name(client):
    await client.get("/roles/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_role(client, csrf_token, name="dupe-role")

    payload = {
        "roles": [
            {
                "name": "dupe-role",
                "description": "different description",
                "require_totp": False,
                "permissions": [],
            }
        ]
    }
    response = await client.post(
        "/roles/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Skipped 1 role (" in response.text
    assert "already exists" in response.text


async def test_import_drops_unknown_permission_with_warning(client):
    await client.get("/roles/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload = {
        "roles": [
            {
                "name": "future-role",
                "description": None,
                "require_totp": False,
                "permissions": ["machine.view", "some.future.permission"],
            }
        ]
    }
    response = await client.post(
        "/roles/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Created 1 role." in response.text
    assert "some.future.permission" in response.text


async def test_import_requires_user_manage_permission(client, login_as):
    from app.db.models.role import Permission

    await login_as(client, permissions={Permission.MACHINE_VIEW})
    await client.get("/roles/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload: dict[str, list[object]] = {"roles": []}
    response = await client.post(
        "/roles/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 403


async def test_api_export_and_import_round_trip(client):
    headers = await _api_token(client)
    await client.get("/roles/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_role(client, csrf_token, name="apiexp-role")

    export_response = await client.get("/api/v1/roles/config/export", headers=headers)
    assert export_response.status_code == 200
    exported = export_response.json()
    assert any(r["name"] == "apiexp-role" for r in exported["roles"])

    import_response = await client.post(
        "/api/v1/roles/config/import", json=exported, headers=headers
    )
    assert import_response.status_code == 200
    result = import_response.json()
    assert any(s["name"] == "apiexp-role" for s in result["skipped_roles"])
