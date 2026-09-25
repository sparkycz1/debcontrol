"""Free-form machine tags — app.services.machine_tags (normalize/parse,
create-or-reuse, orphan cleanup), the web UI (create/edit forms, the list
filter), and the REST API (tags in the machine payload, ?tag= filter,
config export/import round-trip).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

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


async def _machine_id_by_name(db_session_factory: Any, name: str) -> uuid.UUID:
    async with db_session_factory() as db:
        result = await db.execute(select(Machine).where(Machine.name == name))
        machine_id: uuid.UUID = result.scalar_one().id
        return machine_id


async def test_bulk_add_tags_leaves_other_tags_untouched(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="bulk-a", tags="existing")
    await _create_machine(client, csrf_token, name="bulk-b", ip_address="10.0.2.1")

    a_id = await _machine_id_by_name(db_session_factory, "bulk-a")
    b_id = await _machine_id_by_name(db_session_factory, "bulk-b")

    response = await client.post(
        "/machines/bulk/tags/add",
        data={
            "csrf_token": csrf_token,
            "machine_ids": [str(a_id), str(b_id)],
            "tags": "prod, web",
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        a = await db.get(Machine, a_id)
        b = await db.get(Machine, b_id)
        await db.refresh(a, attribute_names=["tags"])
        await db.refresh(b, attribute_names=["tags"])
        assert sorted(t.name for t in a.tags) == ["existing", "prod", "web"]
        assert sorted(t.name for t in b.tags) == ["prod", "web"]


async def test_bulk_remove_tags_leaves_other_tags_and_is_a_noop_if_absent(
    client, db_session_factory
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="bulk-c", tags="prod, web")
    await _create_machine(client, csrf_token, name="bulk-d", ip_address="10.0.2.2")

    c_id = await _machine_id_by_name(db_session_factory, "bulk-c")
    d_id = await _machine_id_by_name(db_session_factory, "bulk-d")  # never had "prod"

    response = await client.post(
        "/machines/bulk/tags/remove",
        data={
            "csrf_token": csrf_token,
            "machine_ids": [str(c_id), str(d_id)],
            "tags": "prod",
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        c = await db.get(Machine, c_id)
        d = await db.get(Machine, d_id)
        await db.refresh(c, attribute_names=["tags"])
        await db.refresh(d, attribute_names=["tags"])
        assert sorted(t.name for t in c.tags) == ["web"]
        assert list(d.tags) == []


async def test_bulk_remove_tags_deletes_orphaned_tag(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="only-one", tags="ephemeral")
    machine_id = await _machine_id_by_name(db_session_factory, "only-one")

    await client.post(
        "/machines/bulk/tags/remove",
        data={"csrf_token": csrf_token, "machine_ids": [str(machine_id)], "tags": "ephemeral"},
    )

    async with db_session_factory() as db:
        result = await db.execute(select(Tag).where(Tag.name == "ephemeral"))
        assert result.scalar_one_or_none() is None


async def test_bulk_add_tags_requires_a_selection_and_a_tag(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines/bulk/tags/add",
        data={"csrf_token": csrf_token, "machine_ids": [], "tags": "prod"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "bulk_error" in response.headers["location"]


async def test_bulk_add_tags_api(client):
    headers = await _api_token(client)
    create_resp = await client.post(
        "/api/v1/machines",
        json={
            "name": "api-bulk-a",
            "ip_address": "10.0.3.1",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
            "secret": "s3cret",
            "tags": ["existing"],
        },
        headers=headers,
    )
    machine_id = create_resp.json()["id"]

    response = await client.post(
        "/api/v1/machines/bulk/tags/add",
        json={"machine_ids": [machine_id], "tags": ["Prod", "web"]},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["machine_count"] == 1

    get_resp = await client.get(f"/api/v1/machines/{machine_id}", headers=headers)
    assert sorted(get_resp.json()["tags"]) == ["existing", "prod", "web"]


async def test_bulk_remove_tags_api(client):
    headers = await _api_token(client)
    create_resp = await client.post(
        "/api/v1/machines",
        json={
            "name": "api-bulk-b",
            "ip_address": "10.0.3.2",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
            "secret": "s3cret",
            "tags": ["prod", "web"],
        },
        headers=headers,
    )
    machine_id = create_resp.json()["id"]

    response = await client.post(
        "/api/v1/machines/bulk/tags/remove",
        json={"machine_ids": [machine_id], "tags": ["prod"]},
        headers=headers,
    )
    assert response.status_code == 200, response.text

    get_resp = await client.get(f"/api/v1/machines/{machine_id}", headers=headers)
    assert get_resp.json()["tags"] == ["web"]


async def test_machine_list_filters_by_multiple_tags_or_mode(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="or-prod", tags="prod")
    await _create_machine(client, csrf_token, name="or-web", ip_address="10.0.4.1", tags="web")
    await _create_machine(client, csrf_token, name="or-neither", ip_address="10.0.4.2")

    response = await client.get("/machines", params=[("tag", "prod"), ("tag", "web")])

    assert "or-prod" in response.text
    assert "or-web" in response.text
    assert "or-neither" not in response.text


async def test_machine_list_has_no_separate_tag_picker(client):
    """Regression guard: the machine list used to have a <select multiple>
    tag picker alongside the plain search box; it's gone now in favor of
    folding tag search into that one field (see the test above) — a
    machine group's own pages keep their one-tag <select>, unaffected."""
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="has-a-tag", tags="prod")

    response = await client.get("/machines")

    assert '<select name="tag"' not in response.text


async def test_machine_list_table_has_its_own_tags_column(client):
    """Tags used to render wrapped under a machine's own name cell; now
    a dedicated column between Group and Status."""
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="tagged-web", tags="prod, web")

    response = await client.get("/machines")

    assert "Tags</th>" in response.text
    row = next(r for r in response.text.split("<tr>") if "tagged-web" in r)
    assert 'href="?tag=prod"' in row
    assert 'href="?tag=web"' in row


async def test_plain_search_box_also_matches_a_tag_name(client):
    """The machine list folds tag search into its one plain search field
    rather than a separate picker control — see machine_search_clause's
    own docstring and partials/machine_search_form.html."""
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="tagged-prod", tags="prod")
    await _create_machine(client, csrf_token, name="untagged", ip_address="10.0.4.9")

    response = await client.get("/machines", params={"q": "prod"})

    assert "tagged-prod" in response.text
    assert "untagged" not in response.text


async def test_machine_list_filters_by_multiple_tags_and_mode(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="and-both", tags="prod, web")
    await _create_machine(
        client, csrf_token, name="and-prod-only", ip_address="10.0.4.3", tags="prod"
    )

    response = await client.get(
        "/machines", params=[("tag", "prod"), ("tag", "web"), ("tag_mode", "and")]
    )

    assert "and-both" in response.text
    assert "and-prod-only" not in response.text


async def test_machines_api_filters_by_multiple_tags(client):
    headers = await _api_token(client)
    await client.post(
        "/api/v1/machines",
        json={
            "name": "api-and-both",
            "ip_address": "10.0.5.1",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
            "secret": "s3cret",
            "tags": ["prod", "web"],
        },
        headers=headers,
    )
    await client.post(
        "/api/v1/machines",
        json={
            "name": "api-prod-only",
            "ip_address": "10.0.5.2",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
            "secret": "s3cret",
            "tags": ["prod"],
        },
        headers=headers,
    )

    or_resp = await client.get(
        "/api/v1/machines", params=[("tag", "prod"), ("tag", "web")], headers=headers
    )
    or_names = {m["name"] for m in or_resp.json()}
    assert {"api-and-both", "api-prod-only"} <= or_names

    and_resp = await client.get(
        "/api/v1/machines",
        params=[("tag", "prod"), ("tag", "web"), ("tag_mode", "and")],
        headers=headers,
    )
    and_names = {m["name"] for m in and_resp.json()}
    assert "api-and-both" in and_names
    assert "api-prod-only" not in and_names


async def test_saved_view_round_trips_multiple_tags_and_mode(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="view-both", tags="prod, web")

    response = await client.post(
        "/machines/views",
        data={
            "csrf_token": csrf_token,
            "name": "prod and web",
            "tag": ["prod", "web"],
            "tag_mode": "and",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "tag=prod" in response.headers["location"]
    assert "tag=web" in response.headers["location"]
    assert "tag_mode=and" in response.headers["location"]

    list_page = await client.get("/machines")
    assert "prod and web" in list_page.text


async def test_inventory_csv_export_respects_filter_and_is_audited(client, db_session_factory):
    import csv
    import io

    from sqlalchemy import select

    from app.db.models.audit_log import AuditLogEntry
    from app.db.models.machine import AuthMethod, Machine

    async with db_session_factory() as session:
        session.add_all(
            [
                Machine(name="inv-web", ip_address="10.1.0.1", username="u",
                        auth_method=AuthMethod.SSH_KEY, is_reachable=True,
                        os_version="Debian 13", upgradable_count=4),
                Machine(name="=cmd-db", ip_address="10.1.0.2", username="u",
                        auth_method=AuthMethod.SSH_KEY),
            ]
        )
        await session.commit()

    everything = await client.get("/machines/inventory.csv")
    assert everything.status_code == 200
    assert everything.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(everything.text)))
    by_name = {row["name"]: row for row in rows}
    assert by_name["inv-web"]["status"] == "online"
    assert by_name["inv-web"]["upgradable"] == "4"
    # Formula-looking cells are neutralized, same as the audit export.
    assert "'=cmd-db" in by_name

    filtered = await client.get("/machines/inventory.csv?q=inv-web")
    assert [row["name"] for row in csv.DictReader(io.StringIO(filtered.text))] == ["inv-web"]

    async with db_session_factory() as session:
        actions = (await session.execute(select(AuditLogEntry.action))).scalars().all()
    assert "machine.inventory_export" in actions
