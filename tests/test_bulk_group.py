"""Bulk "Move to group" from the machine list, and its API twin."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from tests.test_api_v1_extended import _api_token


async def _seed(db_session_factory: Any) -> tuple[list[uuid.UUID], uuid.UUID, uuid.UUID]:
    async with db_session_factory() as session:
        prod, dev = MachineGroup(name="prod"), MachineGroup(name="dev")
        session.add_all([prod, dev])
        await session.flush()
        machines = [
            Machine(name=f"m{i}", ip_address=f"10.9.0.{i}", username="u",
                    auth_method=AuthMethod.SSH_KEY, group_id=dev.id)
            for i in range(3)
        ]
        session.add_all(machines)
        await session.commit()
        return [m.id for m in machines], prod.id, dev.id


async def _groups(db_session_factory: Any) -> dict[str, uuid.UUID | None]:
    async with db_session_factory() as session:
        rows = (await session.execute(select(Machine.name, Machine.group_id))).all()
    return dict(rows)


async def test_web_bulk_move_and_clear(client, db_session_factory):
    ids, prod_id, _dev_id = await _seed(db_session_factory)
    await client.get("/machines")
    csrf = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines/bulk/group",
        data={"csrf_token": csrf, "machine_ids": [str(ids[0]), str(ids[1])],
              "group_id": str(prod_id)},
    )
    assert response.status_code == 303
    followed = await client.get(response.headers["location"])
    assert 'Moved 2 machines to group "prod".' in followed.text.replace("&#34;", '"')
    groups = await _groups(db_session_factory)
    assert groups["m0"] == prod_id and groups["m1"] == prod_id and groups["m2"] != prod_id

    cleared = await client.post(
        "/machines/bulk/group",
        data={"csrf_token": csrf, "machine_ids": [str(ids[2])], "group_id": "none"},
    )
    assert cleared.status_code == 303
    assert (await _groups(db_session_factory))["m2"] is None

    nothing_picked = await client.post(
        "/machines/bulk/group",
        data={"csrf_token": csrf, "machine_ids": [str(ids[0])], "group_id": ""},
    )
    assert "bulk_error" in nothing_picked.headers["location"]
    assert (await _groups(db_session_factory))["m0"] == prod_id

    async with db_session_factory() as session:
        actions = (await session.execute(select(AuditLogEntry.action))).scalars().all()
    assert actions.count("machines.bulk.group.assign") == 2


async def test_web_bulk_move_rejects_unknown_group(client, db_session_factory):
    ids, _prod_id, dev_id = await _seed(db_session_factory)
    await client.get("/machines")
    csrf = client.cookies.get("csrftoken")
    response = await client.post(
        "/machines/bulk/group",
        data={"csrf_token": csrf, "machine_ids": [str(ids[0])], "group_id": str(uuid.uuid4())},
    )
    assert "bulk_error" in response.headers["location"]
    assert (await _groups(db_session_factory))["m0"] == dev_id


async def test_restricted_user_cannot_move_into_hidden_group_or_ungroup(
    client, db_session_factory, login_as
):
    ids, prod_id, dev_id = await _seed(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.MACHINE_MANAGE},
                   group_ids={dev_id})
    await client.get("/machines")
    csrf = client.cookies.get("csrftoken")
    for target in (str(prod_id), "none", ""):
        response = await client.post(
            "/machines/bulk/group",
            data={"csrf_token": csrf, "machine_ids": [str(ids[0])], "group_id": target},
        )
        assert "bulk_error" in response.headers["location"]
    assert (await _groups(db_session_factory))["m0"] == dev_id


async def test_api_bulk_move(client, db_session_factory):
    ids, prod_id, _dev_id = await _seed(db_session_factory)
    headers = await _api_token(client)
    response = await client.post(
        "/api/v1/machines/bulk/group",
        json={"machine_ids": [str(i) for i in ids], "group_id": str(prod_id)},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert len(response.json()["moved"]) == 3
    again = await client.post(
        "/api/v1/machines/bulk/group",
        json={"machine_ids": [str(ids[0])], "group_id": str(prod_id)},
        headers=headers,
    )
    assert again.json() == {"group_id": str(prod_id), "moved": [], "unchanged_count": 1}


async def test_web_bulk_check_updates_says_how_many_started(client, db_session_factory):
    ids, _prod_id, _dev_id = await _seed(db_session_factory)
    async with db_session_factory() as session:
        for machine in (await session.execute(select(Machine))).scalars():
            if machine.id != ids[2]:
                machine.host_key_fingerprint = "SHA256:x"
        await session.commit()
    await client.get("/machines")
    response = await client.post(
        "/machines/bulk/check-updates",
        data={"csrf_token": client.cookies.get("csrftoken"), "machine_ids": [str(i) for i in ids]},
    )
    assert response.status_code == 303
    followed = await client.get(response.headers["location"])
    assert "Update check started on 2 machines" in followed.text
    assert "1 skipped (host key not confirmed)." in followed.text
