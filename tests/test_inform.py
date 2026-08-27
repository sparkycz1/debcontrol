from __future__ import annotations

import re

INFORM_TOKEN = "test-only-inform-token-not-for-real-use-000000"


async def test_inform_requires_bearer_token(client):
    response = await client.post("/api/inform", json={"hostname": "web1"})
    assert response.status_code == 401


async def test_inform_rejects_wrong_token(client):
    response = await client.post(
        "/api/inform",
        json={"hostname": "web1"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401


async def test_inform_creates_pending_machine(client):
    response = await client.post(
        "/api/inform",
        json={
            "hostname": "web1",
            "ip_address": "10.0.0.30",
            "os_version": "Debian GNU/Linux 12 (bookworm)",
            "kernel_version": "6.1.0-13-amd64",
            "cpu_cores": 2,
            "ram_bytes": 2147483648,
        },
        headers={"Authorization": f"Bearer {INFORM_TOKEN}"},
    )
    assert response.status_code == 201

    listing = await client.get("/machines")
    assert listing.status_code == 200
    assert "10.0.0.30" in listing.text
    assert "web1" in listing.text


async def test_inform_falls_back_to_request_source_ip(client):
    response = await client.post(
        "/api/inform",
        json={"hostname": "web2"},
        headers={"Authorization": f"Bearer {INFORM_TOKEN}"},
    )
    assert response.status_code == 201

    listing = await client.get("/machines")
    assert "web2" in listing.text


async def test_dismiss_pending_machine(client):
    await client.post(
        "/api/inform",
        json={"hostname": "web3", "ip_address": "10.0.0.31"},
        headers={"Authorization": f"Bearer {INFORM_TOKEN}"},
    )
    listing = await client.get("/machines")
    assert "10.0.0.31" in listing.text
    csrf_token = client.cookies.get("csrftoken")

    # Find the pending machine's id from the dismiss form action in the HTML.
    match = re.search(r"/machines/pending/([0-9a-f-]+)/dismiss", listing.text)
    assert match is not None
    pending_id = match.group(1)

    dismiss = await client.post(
        f"/machines/pending/{pending_id}/dismiss",
        data={"csrf_token": csrf_token},
    )
    assert dismiss.status_code == 303

    listing = await client.get("/machines")
    assert "10.0.0.31" not in listing.text
