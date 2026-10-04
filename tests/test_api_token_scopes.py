"""Limits on a single API token: read-only, and machine groups — on top of
whatever the owning account may do (`ApiToken.read_only`,
`ApiToken.machine_group_ids`)."""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.api_token import ApiToken
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.user import User


async def _fleet(db_session_factory: Any) -> tuple[Any, Any]:
    async with db_session_factory() as db:
        web, mail = MachineGroup(name="Web"), MachineGroup(name="Mail")
        db.add_all([web, mail])
        await db.flush()
        for name, ip, group in (("web1", "10.0.0.1", web), ("mail1", "10.0.0.2", mail)):
            db.add(
                Machine(
                    name=name,
                    ip_address=ip,
                    port=22,
                    username="root",
                    auth_method=AuthMethod.PASSWORD,
                    group_id=group.id,
                )
            )
        db.add(
            Machine(
                name="loose",
                ip_address="10.0.0.3",
                port=22,
                username="root",
                auth_method=AuthMethod.PASSWORD,
            )
        )
        await db.commit()
        return web.id, mail.id


async def _token(db_session_factory: Any, **limits: Any) -> dict[str, str]:
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None
        user.api_access_enabled = True
        await db.commit()
        _token, raw = await create_api_token(db, user, name="t", expires_at=None, **limits)
    return {"Authorization": f"Bearer {raw}"}


async def _names(client: Any, headers: dict[str, str]) -> set[str]:
    response = await client.get("/api/v1/machines", headers=headers)
    assert response.status_code == 200
    body = response.json()
    return {machine["name"] for machine in (body["machines"] if isinstance(body, dict) else body)}


async def test_read_only_token_reads_but_never_writes(client: Any, db_session_factory: Any) -> None:
    web_id, _mail_id = await _fleet(db_session_factory)
    headers = await _token(db_session_factory, read_only=True)

    assert await _names(client, headers) == {"web1", "mail1", "loose"}
    created = await client.post(
        "/api/v1/machine-groups", json={"name": "New"}, headers=headers
    )
    assert created.status_code == 403
    assert created.json()["detail"] == "This API token is read-only."
    deleted = await client.delete(f"/api/v1/machine-groups/{web_id}", headers=headers)
    assert deleted.status_code == 403
    async with db_session_factory() as db:
        assert await db.get(MachineGroup, web_id) is not None


async def test_group_limited_token_sees_only_its_groups(
    client: Any, db_session_factory: Any
) -> None:
    web_id, _mail_id = await _fleet(db_session_factory)
    headers = await _token(db_session_factory, machine_group_ids=[web_id])

    assert await _names(client, headers) == {"web1"}
    found = await client.get("/api/v1/search", params={"q": "10.0.0"}, headers=headers)
    labels = [hit["label"] for group in found.json()["results"] for hit in group["hits"]]
    assert labels == ["web1"]

    # The same account without a limited token still sees everything.
    assert await _names(client, await _token(db_session_factory)) == {"web1", "mail1", "loose"}


async def test_token_whose_groups_are_gone_sees_nothing(
    client: Any, db_session_factory: Any
) -> None:
    web_id, _mail_id = await _fleet(db_session_factory)
    headers = await _token(db_session_factory, machine_group_ids=[web_id])
    async with db_session_factory() as db:
        group = await db.get(MachineGroup, web_id)
        await db.delete(group)
        await db.commit()

    assert await _names(client, headers) == set()


async def test_limited_tokens_cannot_register_a_machine(
    client: Any, db_session_factory: Any
) -> None:
    web_id, _mail_id = await _fleet(db_session_factory)
    payload = {"hostname": "new-host", "os": "Debian 13"}
    for limits in ({"read_only": True}, {"machine_group_ids": [web_id]}):
        headers = await _token(db_session_factory, **limits)
        response = await client.post("/api/inform", json=payload, headers=headers)
        assert response.status_code in (401, 403)


async def test_account_page_creates_a_limited_token(client: Any, db_session_factory: Any) -> None:
    web_id, _mail_id = await _fleet(db_session_factory)
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None
        user.api_access_enabled = True
        await db.commit()

    page = await client.get("/account")
    assert 'name="read_only"' in page.text and 'name="group_ids"' in page.text
    created = await client.post(
        "/account/api-tokens",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "name": "grafana",
            "read_only": "on",
            "group_ids": [str(web_id)],
        },
    )
    assert created.status_code == 200
    raw = re.search(r"dcpat_[A-Za-z0-9_-]+", created.text)
    assert raw is not None
    assert "read-only" in created.text

    async with db_session_factory() as db:
        token = (await db.execute(select(ApiToken))).scalar_one()
        assert token.read_only is True
        assert token.machine_group_ids == [str(web_id)]

    headers = {"Authorization": f"Bearer {raw.group(0)}"}
    assert await _names(client, headers) == {"web1"}
