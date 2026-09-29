"""Machine list Status/Group filters (and their saved views), saved Logs
views, and the journal priority filter."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_change import MachineChange
from app.db.models.machine_group import MachineGroup
from app.db.models.saved_log_view import SavedLogView
from app.db.models.saved_machine_view import SavedMachineView
from app.services.saved_log_views import build_log_query_string
from app.ssh.logs import build_follow_command, build_journal_command
from tests.test_api_v1_extended import _api_token


async def _machines(db_session_factory: Any) -> dict[str, Any]:
    async with db_session_factory() as db:
        group = MachineGroup(name="prod")
        db.add(group)
        await db.flush()

        def make(name: str, **fields: Any) -> Machine:
            machine = Machine(
                name=name, ip_address="10.0.0.1", port=22, username="root",
                auth_method=AuthMethod.PASSWORD, host_key_fingerprint="SHA256:x", **fields,
            )
            db.add(machine)
            return machine

        make("alpha-offline", is_reachable=False)
        make("bravo-security", security_upgradable_count=2, upgradable_count=3,
             group_id=group.id)
        make("charlie-reboot", reboot_required=True)
        delta = make("delta-changed")
        await db.flush()
        db.add(
            MachineChange(
                machine_id=delta.id, detected_at=datetime.now(UTC), category="facts",
                field="kernel_version", old_value="1", new_value="2",
            )
        )
        await db.commit()
        return {"group_id": group.id}


async def test_status_and_group_filters(client, db_session_factory):
    ids = await _machines(db_session_factory)

    def names(text: str) -> set[str]:
        return {n for n in ("alpha-offline", "bravo-security", "charlie-reboot",
                            "delta-changed") if n in text}

    assert names((await client.get("/machines?status=offline")).text) == {"alpha-offline"}
    assert names((await client.get("/machines?status=security")).text) == {"bravo-security"}
    assert names((await client.get("/machines?status=updates")).text) == {"bravo-security"}
    assert names((await client.get("/machines?status=reboot")).text) == {"charlie-reboot"}
    assert names((await client.get("/machines?status=changed")).text) == {"delta-changed"}
    assert names((await client.get(f"/machines?group={ids['group_id']}")).text) == {
        "bravo-security"
    }
    assert "bravo-security" not in (await client.get("/machines?group=none")).text
    # Unknown values are ignored, not errors.
    assert len(names((await client.get("/machines?status=bogus&group=x")).text)) == 4

    headers = await _api_token(client)
    api = await client.get("/api/v1/machines?status=reboot", headers=headers)
    assert [m["name"] for m in api.json()] == ["charlie-reboot"]


async def test_saved_view_keeps_status_and_group(client, db_session_factory):
    ids = await _machines(db_session_factory)
    await client.get("/machines")
    csrf = str(client.cookies.get("csrftoken"))

    response = await client.post(
        "/machines/views",
        data={"csrf_token": csrf, "name": "prod security", "status": "security",
              "group": str(ids["group_id"])},
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        (view,) = (await db.execute(select(SavedMachineView))).scalars().all()
    assert view.query_string == f"status=security&group={ids['group_id']}"

    headers = await _api_token(client)
    created = await client.post(
        "/api/v1/account/saved-views",
        json={"name": "offline", "status": "offline", "group": "garbage"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["query_string"] == "status=offline"


def test_journal_priority_is_whitelisted() -> None:
    assert "-p err" in build_journal_command(
        lines=10, search="", since="", until="", priority="err"
    )
    assert " -p " not in build_journal_command(
        lines=10, search="", since="", until="", priority="err; reboot"
    )
    assert "-p warning" in build_follow_command(
        source="journal", path="", container="", search="", priority="WARNING"
    )


def test_log_query_string_keeps_only_known_values() -> None:
    assert build_log_query_string(
        {"source": "journal", "priority": "err", "since": "-1h", "evil": "x", "lines": "abc"}
    ) == "source=journal&priority=err&since=-1h"
    assert build_log_query_string({"source": "ftp", "priority": "nope"}) == ""


async def test_save_and_delete_a_log_view(client, db_session_factory):
    async with db_session_factory() as db:
        machine = Machine(
            name="web1", ip_address="10.0.0.1", port=22, username="root",
            auth_method=AuthMethod.PASSWORD, host_key_fingerprint="SHA256:x",
        )
        db.add(machine)
        await db.commit()
        machine_id = machine.id

    page = await client.get(f"/machines/{machine_id}/logs?source=journal&priority=err")
    assert page.status_code == 200
    assert 'value="err" selected' in page.text
    csrf = str(client.cookies.get("csrftoken"))

    saved = await client.post(
        f"/machines/{machine_id}/logs/views",
        data={"csrf_token": csrf, "name": "errors", "source": "journal", "priority": "err",
              "since": "-1h"},
    )
    assert saved.status_code == 303
    async with db_session_factory() as db:
        (view,) = (await db.execute(select(SavedLogView))).scalars().all()
    assert view.query_string == "source=journal&priority=err&since=-1h"

    page = await client.get(f"/machines/{machine_id}/logs")
    assert f"/machines/{machine_id}/logs?source=journal&amp;priority=err" in page.text

    duplicate = await client.post(
        f"/machines/{machine_id}/logs/views",
        data={"csrf_token": csrf, "name": "errors", "source": "journal"},
    )
    assert "view_error=duplicate_name" in duplicate.headers["location"]

    deleted = await client.post(
        f"/machines/{machine_id}/logs/views/{view.id}/delete", data={"csrf_token": csrf}
    )
    assert deleted.status_code == 303
    async with db_session_factory() as db:
        assert (await db.execute(select(SavedLogView))).scalars().all() == []


async def test_log_views_api(client):
    headers = await _api_token(client)
    created = await client.post(
        "/api/v1/account/saved-log-views",
        json={"name": "nginx 502", "source": "file", "path": "/var/log/nginx/error.log",
              "search": "502", "lines": 500},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["query_string"] == (
        "source=file&path=%2Fvar%2Flog%2Fnginx%2Ferror.log&search=502&lines=500"
    )
    listed = await client.get("/api/v1/account/saved-log-views", headers=headers)
    assert [v["name"] for v in listed.json()] == ["nginx 502"]
    conflict = await client.post(
        "/api/v1/account/saved-log-views", json={"name": "nginx 502"}, headers=headers
    )
    assert conflict.status_code == 409
    view_id = created.json()["id"]
    deleted = await client.delete(f"/api/v1/account/saved-log-views/{view_id}", headers=headers)
    assert deleted.status_code == 204
