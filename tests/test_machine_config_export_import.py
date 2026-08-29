"""Export/import of machine & group configuration (Task 1) — see
`app/services/machine_config.py` for the design (what's excluded, and the
conflict-handling policy) and `app/web/routes/machines.py` /
`app/web/routes/api_v1.py` for the web/API routes.
"""

from __future__ import annotations

import json
import re

from httpx import AsyncClient

from tests.test_web import _create_machine


async def _api_token(client: AsyncClient) -> dict[str, str]:
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "config-test", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None
    return {"Authorization": f"Bearer {match.group(1)}"}


async def test_export_json_excludes_secrets_and_fingerprints(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(
        client,
        csrf_token,
        name="exp1",
        ip_address="10.20.0.1",
        auth_method="password",
        secret="super-secret-password",
    )

    response = await client.get("/machines/config/export?format=json")
    assert response.status_code == 200
    data = response.json()
    assert len(data["machines"]) == 1
    machine = data["machines"][0]
    assert machine["name"] == "exp1"
    assert machine["auth_method"] == "password"
    assert "secret_encrypted" not in machine
    assert "secret" not in machine
    assert "host_key_fingerprint" not in machine


async def test_export_csv_lists_machines_only(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="exp2", ip_address="10.20.0.2")

    response = await client.get("/machines/config/export?format=csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "exp2" in response.text
    assert "secret" not in response.text.lower() or "secret_encrypted" not in response.text


async def test_export_includes_group_membership(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    group_resp = await client.post(
        "/machine-groups",
        data={"name": "exportgroup", "description": "", "csrf_token": csrf_token},
    )
    group_url = group_resp.headers["location"]
    machine_id = await _create_machine(client, csrf_token, name="exp3", ip_address="10.20.0.3")
    await client.post(
        f"{group_url}/machines",
        data={"machine_id": str(machine_id), "csrf_token": csrf_token},
    )

    response = await client.get("/machines/config/export?format=json")
    data = response.json()
    machine = next(m for m in data["machines"] if m["name"] == "exp3")
    assert machine["group"] == "exportgroup"
    group = next(g for g in data["groups"] if g["name"] == "exportgroup")
    assert "exp3" in group["members"]


async def test_import_creates_machines_and_groups(client):
    await client.get("/machines/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload = {
        "machines": [
            {
                "name": "imp1",
                "ip_address": "10.30.0.1",
                "port": 22,
                "username": "admin",
                "auth_method": "ssh_key",
                "group": "importedgroup",
                "description": "restored",
                "is_active": True,
            }
        ],
        "groups": [{"name": "importedgroup", "description": "a group", "members": ["imp1"]}],
    }
    response = await client.post(
        "/machines/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Created 1 machine(s)" in response.text
    assert "1 group(s)" in response.text

    machines_page = await client.get("/machines")
    assert "imp1" in machines_page.text

    groups_page = await client.get("/machine-groups")
    assert "importedgroup" in groups_page.text


async def test_import_downgrades_password_auth_with_warning(client):
    await client.get("/machines/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload = {
        "machines": [
            {
                "name": "imp2",
                "ip_address": "10.30.0.2",
                "port": 22,
                "username": "admin",
                "auth_method": "password",
            }
        ],
        "groups": [],
    }
    response = await client.post(
        "/machines/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "originally used password authentication" in response.text
    assert "imp2" in response.text

    detail_search = await client.get("/machines?q=imp2")
    assert "imp2" in detail_search.text


async def test_import_skips_existing_machine_name(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="dupe", ip_address="10.30.0.3")

    payload = {
        "machines": [
            {
                "name": "dupe",
                "ip_address": "10.30.0.99",
                "port": 22,
                "username": "admin",
                "auth_method": "ssh_key",
            }
        ],
        "groups": [],
    }
    response = await client.post(
        "/machines/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Skipped 1 machine(s)" in response.text
    assert "already exists" in response.text


async def test_import_requires_machine_manage_permission(client, login_as):
    from app.db.models.role import Permission

    await login_as(client, permissions={Permission.MACHINE_VIEW})
    await client.get("/machines/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload: dict[str, list[object]] = {"machines": [], "groups": []}
    response = await client.post(
        "/machines/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 403


async def test_api_export_and_import_round_trip(client):
    headers = await _api_token(client)
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="apiexp1", ip_address="10.40.0.1")

    export_response = await client.get("/api/v1/machines/config/export", headers=headers)
    assert export_response.status_code == 200
    exported = export_response.json()
    assert any(m["name"] == "apiexp1" for m in exported["machines"])

    # Round-trip it back in (would be skipped since it already exists).
    import_response = await client.post(
        "/api/v1/machines/config/import", json=exported, headers=headers
    )
    assert import_response.status_code == 200
    result = import_response.json()
    assert any(s["name"] == "apiexp1" for s in result["skipped_machines"])
