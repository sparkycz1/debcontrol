"""The status page (`app.services.status_page`): off by default, opened
only by its own link, and showing nothing but names and whether they are
up."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.core.app_settings import get_or_create_app_settings
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.db.models.machine_reachability_sample import MachineReachabilitySample
from app.services import status_page
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token


async def _seed(db_session_factory: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    web = await _add_machine(
        db_session_factory, name="Web server", ip_address="203.0.113.10", is_reachable=True
    )
    hidden = await _add_machine(
        db_session_factory, name="internal-db", ip_address="203.0.113.11", is_reachable=False
    )
    async with db_session_factory() as db:
        shop = EndpointCheck(
            name="Shop",
            kind="http",
            target="https://shop.internal.example/health",
            last_ok=False,
            last_error="connect timeout to 10.1.2.3",
            enabled=True,
        )
        secret = EndpointCheck(
            name="secret-admin", kind="http", target="https://admin.example", last_ok=True
        )
        db.add_all([shop, secret])
        await db.flush()
        for index in range(4):
            db.add(
                EndpointCheckResult(
                    check_id=shop.id, checked_at=now - timedelta(hours=index), ok=index != 0
                )
            )
            db.add(
                MachineReachabilitySample(
                    machine_id=web, checked_at=now - timedelta(hours=index), reachable=True
                )
            )
        # Too old to count.
        db.add(EndpointCheckResult(check_id=shop.id, checked_at=now - timedelta(days=40), ok=False))
        await db.commit()
        return {"web": web, "hidden": hidden, "shop": shop.id, "secret": secret.id}


async def test_off_by_default_and_only_the_link_opens_it(
    client: AsyncClient, db_session_factory: Any
) -> None:
    ids = await _seed(db_session_factory)
    status_page.invalidate()
    await client.get("/checks/status-page")
    csrf = client.cookies.get("csrftoken")

    before = await client.get("/status/anything")
    saved = await client.post(
        "/checks/status-page",
        data={
            "csrf_token": csrf,
            "enabled": "true",
            "title": "Our services",
            "check_ids": str(ids["shop"]),
            "machine_ids": str(ids["web"]),
        },
        follow_redirects=False,
    )
    async with db_session_factory() as db:
        token = (await get_or_create_app_settings(db)).status_page_token
    assert token is not None
    settings_page = await client.get("/checks/status-page")

    # A visitor: no session cookie at all.
    client.cookies.clear()
    page = await client.get(f"/status/{token}")
    data = (await client.get(f"/status/{token}.json")).json()
    wrong = await client.get(f"/status/{token}x")
    still_private = await client.get("/checks/status-page", follow_redirects=False)

    assert before.status_code == 404
    assert saved.status_code == 303
    assert f"/status/{token}" in settings_page.text
    assert page.status_code == 200 and wrong.status_code == 404
    assert still_private.status_code in (303, 401, 403)
    assert "Our services" in page.text and "Not everything is working: 1 down." in page.text
    assert data["overall"] == "down"
    assert data["items"] == [
        {"kind": "check", "name": "Shop", "state": "down", "uptime_percent": 75.0},
        {"kind": "machine", "name": "Web server", "state": "up", "uptime_percent": 100.0},
    ]
    # Nothing that was not chosen, and nothing but names.
    for leak in ("internal-db", "secret-admin", "203.0.113", "shop.internal", "connect timeout"):
        assert leak not in page.text, leak
    assert page.headers["cache-control"] == "no-store"
    assert "noindex" in page.headers["x-robots-tag"]


async def test_a_new_link_closes_the_old_one_and_off_means_gone(
    client: AsyncClient, db_session_factory: Any
) -> None:
    ids = await _seed(db_session_factory)
    status_page.invalidate()
    headers = await _api_token(client)

    first = (
        await client.put(
            "/api/v1/status-page",
            headers=headers,
            json={"enabled": True, "machine_ids": [str(ids["web"])]},
        )
    ).json()
    second = (
        await client.put(
            "/api/v1/status-page",
            headers=headers,
            json={"enabled": True, "machine_ids": [str(ids["web"])], "new_link": True},
        )
    ).json()
    old = await client.get(first["path"])
    new = await client.get(second["path"])
    off = (await client.put("/api/v1/status-page", headers=headers, json={"enabled": False})).json()
    gone = await client.get(second["path"])

    assert first["path"] != second["path"]
    assert (old.status_code, new.status_code, gone.status_code) == (404, 200, 404)
    assert "All systems operational." in new.text
    assert off["path"] is None and off["enabled"] is False
    async with db_session_factory() as db:
        from app.db.models.audit_log import AuditLogEntry

        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert actions.count("status_page.update") == 3
