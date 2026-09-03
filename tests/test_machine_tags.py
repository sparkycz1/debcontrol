"""Free-form machine tags — app.services.machine_tags (normalize/parse,
create-or-reuse, orphan cleanup), the web UI (create/edit forms, the list
filter), and the REST API (tags in the machine payload, ?tag= filter,
config export/import round-trip).
"""

from __future__ import annotations

import json

from sqlalchemy import select

from app.db.models.machine import Machine
from app.db.models.machine_tag import Tag
from app.services.machine_tags import (
    normalize_tag_names,
    parse_tag_names_from_text,
    set_machine_tags,
)
from tests.test_api_v1_extended import _api_token
from tests.test_web import _create_machine


def test_normalize_tag_names_lowercases_trims_and_dedupes():
    assert normalize_tag_names([" Prod ", "prod", "Web"]) == ["prod", "web"]


def test_normalize_tag_names_drops_blanks():
    assert normalize_tag_names(["", "   ", "prod"]) == ["prod"]


def test_normalize_tag_names_caps_length():
    long_name = "x" * 100
    assert normalize_tag_names([long_name]) == ["x" * 64]


def test_parse_tag_names_from_text_splits_on_comma_and_newline():
    assert parse_tag_names_from_text("prod, web\nstaging") == ["prod", "web", "staging"]


async def test_set_machine_tags_creates_new_tags(client, db_session_factory):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        await set_machine_tags(db, machine, ["prod", "web"])
        await db.commit()

    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        assert sorted(tag.name for tag in machine.tags) == ["prod", "web"]
        all_tags = (await db.execute(select(Tag))).scalars().all()
        assert {t.name for t in all_tags} == {"prod", "web"}


async def test_set_machine_tags_reuses_an_existing_tag(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id_1 = await _create_machine(client, csrf_token, name="m1")
    machine_id_2 = await _create_machine(
        client, csrf_token, name="m2", ip_address="10.0.1.2"
    )
    async with db_session_factory() as db:
        m1 = await db.get(Machine, machine_id_1)
        assert m1 is not None
        await set_machine_tags(db, m1, ["prod"])
        await db.commit()
        m2 = await db.get(Machine, machine_id_2)
        assert m2 is not None
        await set_machine_tags(db, m2, ["prod"])
        await db.commit()

    async with db_session_factory() as db:
        all_tags = (await db.execute(select(Tag))).scalars().all()
        assert len(all_tags) == 1  # one shared row, not two


async def test_set_machine_tags_deletes_an_orphaned_tag(client, db_session_factory):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        await set_machine_tags(db, machine, ["prod"])
        await db.commit()

    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        await set_machine_tags(db, machine, [])  # remove it
        await db.commit()

    async with db_session_factory() as db:
        all_tags = (await db.execute(select(Tag))).scalars().all()
        assert all_tags == []  # the now-unused tag row is gone


async def test_set_machine_tags_keeps_a_tag_still_used_elsewhere(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id_1 = await _create_machine(client, csrf_token, name="m1")
    machine_id_2 = await _create_machine(
        client, csrf_token, name="m2", ip_address="10.0.1.2"
    )
    async with db_session_factory() as db:
        m1 = await db.get(Machine, machine_id_1)
        m2 = await db.get(Machine, machine_id_2)
        assert m1 is not None and m2 is not None
        await set_machine_tags(db, m1, ["prod"])
        await set_machine_tags(db, m2, ["prod"])
        await db.commit()

    async with db_session_factory() as db:
        m1 = await db.get(Machine, machine_id_1)
        assert m1 is not None
        await set_machine_tags(db, m1, [])
        await db.commit()

    async with db_session_factory() as db:
        all_tags = (await db.execute(select(Tag))).scalars().all()
        assert [t.name for t in all_tags] == ["prod"]  # m2 still uses it


async def test_create_machine_web_form_sets_tags(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, tags="Prod, Web")

    response = await client.get(f"/machines/{machine_id}")
    assert "prod" in response.text
    assert "web" in response.text


async def test_edit_machine_web_form_updates_tags(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, tags="prod")

    edit_data = {
        "name": "m",
        "ip_address": "10.0.1.1",
        "port": "22",
        "username": "admin",
        "auth_method": "password",
        "tags": "staging",
        "csrf_token": csrf_token,
    }
    response = await client.post(f"/machines/{machine_id}/edit", data=edit_data)
    assert response.status_code == 303

    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        assert [t.name for t in machine.tags] == ["staging"]


async def test_machine_list_filters_by_tag(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="prod-box", tags="prod")
    await _create_machine(
        client, csrf_token, name="dev-box", ip_address="10.0.1.9", tags="dev"
    )

    response = await client.get("/machines", params={"tag": "prod"})

    assert "prod-box" in response.text
    assert "dev-box" not in response.text


async def test_machines_api_returns_and_filters_by_tags(client):
    headers = await _api_token(client)
    create_resp = await client.post(
        "/api/v1/machines",
        json={
            "name": "api-tagged",
            "ip_address": "10.0.2.1",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
            "secret": "s3cret",
            "tags": ["Prod", "prod", "web"],
        },
        headers=headers,
    )
    assert create_resp.status_code == 201, create_resp.text
    assert sorted(create_resp.json()["tags"]) == ["prod", "web"]

    list_resp = await client.get("/api/v1/machines", params={"tag": "prod"}, headers=headers)
    assert list_resp.status_code == 200
    names = [m["name"] for m in list_resp.json()]
    assert "api-tagged" in names

    list_resp_other = await client.get(
        "/api/v1/machines", params={"tag": "nonexistent"}, headers=headers
    )
    assert list_resp_other.json() == []


async def test_machines_api_update_replaces_tags(client):
    headers = await _api_token(client)
    create_resp = await client.post(
        "/api/v1/machines",
        json={
            "name": "api-retag",
            "ip_address": "10.0.2.2",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
            "secret": "s3cret",
            "tags": ["prod"],
        },
        headers=headers,
    )
    machine_id = create_resp.json()["id"]

    update_resp = await client.put(
        f"/api/v1/machines/{machine_id}",
        json={
            "name": "api-retag",
            "ip_address": "10.0.2.2",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
            "is_active": True,
            "tags": ["staging"],
        },
        headers=headers,
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["tags"] == ["staging"]


async def test_config_export_import_round_trips_tags(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="export-me", tags="prod, web")

    export_resp = await client.get("/machines/config/export", params={"format": "json"})
    assert export_resp.status_code == 200
    payload = export_resp.json()
    exported = next(m for m in payload["machines"] if m["name"] == "export-me")
    assert sorted(exported["tags"]) == ["prod", "web"]

    # Re-import under a new name (the original name already exists, so a
    # same-named import would just be skipped — see machine_config's
    # module docstring) to confirm tags survive an import too.
    payload["machines"][0] = {**exported, "name": "reimported-me"}
    payload["machines"] = [payload["machines"][0]]
    payload["groups"] = []
    import_resp = await client.post(
        "/machines/config/import",
        data={"csrf_token": csrf_token, "json_text": json.dumps(payload)},
    )
    assert import_resp.status_code == 200, import_resp.text

    async with db_session_factory() as db:
        result = await db.execute(select(Machine).where(Machine.name == "reimported-me"))
        reimported = result.scalar_one_or_none()
        assert reimported is not None
        assert sorted(tag.name for tag in reimported.tags) == ["prod", "web"]
