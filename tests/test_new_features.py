"""Tests for the six follow-up features added after the initial auth/RBAC
work: per-IP rate limiting is covered in `tests/test_auth.py` instead, since
it's part of the login flow — this file covers the dashboard, per-user API
tokens, SSH key rotation, and CSV bulk import."""

from __future__ import annotations

import re

from httpx import AsyncClient
from sqlalchemy import select

from app.db.models.pending_machine import PendingMachine


async def test_dashboard_renders_for_full_permission_user(client):
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert "Dashboard" in response.text


async def test_dashboard_hides_sections_without_permission(client, login_as):
    from app.db.models.role import Permission

    await login_as(client, permissions={Permission.MACHINE_VIEW})
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert "Scheduling" not in response.text
    assert "Recent activity" not in response.text


async def test_bulk_import_creates_pending_machines(client, db_session_factory):
    await client.get("/machines/import")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines/import",
        data={
            "csv_text": "ip_address,hostname\n10.0.1.10,web1\n10.0.1.11,web2\n,skip-me\n",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 200
    assert "Added 2 pending machine(s)" in response.text
    assert "Skipped 1 row(s)" in response.text

    async with db_session_factory() as db:
        result = await db.execute(select(PendingMachine))
        ips = {p.ip_address for p in result.scalars().all()}
    assert {"10.0.1.10", "10.0.1.11"} <= ips


async def test_bulk_import_rejects_csv_without_ip_address_column(client):
    await client.get("/machines/import")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines/import",
        data={"csv_text": "hostname\nweb1\n", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "ip_address" in response.text
    assert "Added" not in response.text


async def _create_api_token(client: AsyncClient, *, name: str = "test-token") -> str:
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": name, "csrf_token": csrf_token}
    )
    assert response.status_code == 200
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None
    return match.group(1)


async def test_api_token_authorizes_read_only_api(client):
    # Create a machine via the normal form so the read API has something to return.
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/machines",
        data={
            "name": "api-test-machine",
            "ip_address": "10.0.2.10",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "s3cret",
            "csrf_token": csrf_token,
        },
    )

    raw_token = await _create_api_token(client)

    response = await client.get(
        "/api/v1/machines", headers={"Authorization": f"Bearer {raw_token}"}
    )
    assert response.status_code == 200
    names = [m["name"] for m in response.json()]
    assert "api-test-machine" in names


async def test_api_token_rejected_without_bearer_header(client):
    response = await client.get("/api/v1/machines")
    assert response.status_code == 401


async def test_revoked_api_token_stops_working(client):
    raw_token = await _create_api_token(client)
    headers = {"Authorization": f"Bearer {raw_token}"}
    assert (await client.get("/api/v1/machines", headers=headers)).status_code == 200

    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    page = await client.get("/account")
    token_id = re.search(r"/account/api-tokens/([0-9a-f-]{36})/revoke", page.text)
    assert token_id is not None
    revoke = await client.post(
        f"/account/api-tokens/{token_id.group(1)}/revoke", data={"csrf_token": csrf_token}
    )
    assert revoke.status_code in (303, 200)

    response = await client.get("/api/v1/machines", headers=headers)
    assert response.status_code == 401


async def test_inform_accepts_api_token_with_machine_manage(client):
    raw_token = await _create_api_token(client, name="inform-token")
    response = await client.post(
        "/api/inform",
        json={"hostname": "self-registered"},
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 201


async def test_ssh_key_rotation_generate_activate_discard(client):
    settings_page = await client.get("/settings")
    assert "Generate replacement key" in settings_page.text
    csrf_token = client.cookies.get("csrftoken")

    generate = await client.post("/settings/ssh-key/generate", data={"csrf_token": csrf_token})
    assert generate.status_code == 303

    after_generate = await client.get("/settings")
    assert "not active yet" in after_generate.text
    assert "Activate new key" in after_generate.text

    discard = await client.post("/settings/ssh-key/discard", data={"csrf_token": csrf_token})
    assert discard.status_code == 303
    after_discard = await client.get("/settings")
    assert "not active yet" not in after_discard.text

    await client.post("/settings/ssh-key/generate", data={"csrf_token": csrf_token})
    activate = await client.post("/settings/ssh-key/activate", data={"csrf_token": csrf_token})
    assert activate.status_code == 303
    after_activate = await client.get("/settings")
    assert "not active yet" not in after_activate.text


async def test_ssh_key_activate_without_pending_key_shows_error(client):
    csrf_token = client.cookies.get("csrftoken")
    if not csrf_token:
        await client.get("/settings")
        csrf_token = client.cookies.get("csrftoken")
    response = await client.post("/settings/ssh-key/activate", data={"csrf_token": csrf_token})
    assert response.status_code == 200
    assert "No pending SSH key to activate" in response.text
