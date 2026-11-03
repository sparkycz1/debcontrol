"""Docker revamp: the fleet-wide Docker tabs besides containers (stacks,
images, volumes, networks, backups, hosts, jobs) — the same tabs and
actions as a machine's own Docker tab, run machine by machine through the
same code (`app.web.routes.docker_ops`) — plus the stored inventory they
read (`app.services.docker_inventory_snapshot`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.db.models.docker import DockerJobKind
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.services import docker_inventory_snapshot as inventory_snapshot
from tests.test_docker_web_support import (
    IMAGE_ID,
    RUN_JOB_TASK,
    VIEWER,
    add_backup,
    add_job,
    add_stack,
    audit_entries,
    follow,
    jobs_of,
    make_docker_machine,
)
from tests.test_update_history import _api_token

KINDS = ("stacks", "images", "volumes", "networks", "backups", "hosts", "jobs")
REFRESH_TASK = "app.tasks.docker_jobs.refresh_docker_inventory"
UNUSED_ID = "sha256:" + "c" * 64


def _inventory() -> dict[str, Any]:
    return {
        "images": [
            {"id": IMAGE_ID, "ref": "nginx:1.27", "repository": "nginx", "tag": "1.27",
             "size_bytes": 1000, "created": "2026-10-01 10:00", "in_use": True},
            {"id": UNUSED_ID, "ref": "busybox:1.37", "repository": "busybox", "tag": "1.37",
             "size_bytes": 10, "created": "2026-09-01 10:00", "in_use": False},
        ],
        "volumes": [
            {"name": "site_data", "driver": "local", "compose_project": "site",
             "used_by": ["web"]},
            {"name": "f00dcafe" * 8, "driver": "local", "anonymous": True, "used_by": []},
        ],
        "networks": [
            {"id": "n1", "name": "bridge", "driver": "bridge", "scope": "local",
             "builtin": True, "containers": []},
            {"id": "n2", "name": "site_default", "driver": "bridge", "scope": "local",
             "containers": ["web"]},
        ],
        "compose": [
            {"name": "site", "status": "running(1)", "config_files": ["/srv/site/compose.yaml"]}
        ],
        "containers": [{"name": "web", "compose_project": "site",
                        "compose_working_dir": "/srv/site"}],
    }


async def _stored_machine(db_session_factory: Any, name: str = "dockerhost") -> uuid.UUID:
    machine_id = await make_docker_machine(db_session_factory, name=name)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        assert inventory_snapshot.store(machine, _inventory(), inventory_snapshot.SECTIONS)
        machine.docker_host_check = {
            "at": datetime.now(UTC).isoformat(),
            "ok": True,
            "facts": {"version": "28.5.1", "storage_driver": "overlay2",
                      "logging_driver": "json-file", "containers": 2, "running": 1},
            "findings": [{"id": "log_rotation", "level": "warn"}],
        }
        await session.commit()
    return machine_id


async def _csrf(client: Any) -> str:
    response = await client.get("/docker/images")
    assert response.status_code == 200
    token = client.cookies.get("csrftoken")
    assert token
    return str(token)


# --- The stored inventory ------------------------------------------------------------


def test_the_snapshot_says_whether_anything_changed() -> None:
    machine = Machine(name="m")
    assert inventory_snapshot.store(machine, _inventory(), inventory_snapshot.SECTIONS)
    assert not inventory_snapshot.store(machine, _inventory(), inventory_snapshot.SECTIONS)
    # Without the in-use information nothing is stored.
    assert not inventory_snapshot.store(machine, {"images": []}, ("images",))
    assert [i["ref"] for i in inventory_snapshot.rows(machine, "images")] == [
        "nginx:1.27", "busybox:1.37",
    ]
    assert inventory_snapshot.project(machine, "site") == {
        "name": "site", "status": "running(1)",
        "config_files": ["/srv/site/compose.yaml"], "working_dir": "/srv/site",
    }
    assert inventory_snapshot.read_at(machine) is not None
    assert inventory_snapshot.rows(machine, "secrets") == []


def test_the_snapshot_trims_what_the_machine_sends() -> None:
    machine = Machine(name="m")
    huge = {"images": [{"id": "x" * 500, "ref": "r" * 900, "size_bytes": "lots"}] * 900}
    inventory_snapshot.store(machine, huge, ("images", "inspect"))
    rows = inventory_snapshot.rows(machine, "images")
    assert len(rows) == 500
    assert len(rows[0]["id"]) == 80 and len(rows[0]["ref"]) == 255
    assert rows[0]["size_bytes"] is None


# --- The pages ------------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
async def test_every_fleet_tab_lists_every_machine(
    client: Any, db_session_factory: Any, kind: str
) -> None:
    first = await _stored_machine(db_session_factory)
    second = await _stored_machine(db_session_factory, name="otherhost")
    await add_stack(db_session_factory, first)
    await add_backup(db_session_factory, second)
    await add_job(db_session_factory, first)

    response = await client.get(f"/docker/{kind}")

    assert response.status_code == 200
    text = response.text
    # The same tabs as a machine's Docker tab, then the fleet-only ones.
    for tab in KINDS:
        assert f'href="/docker/{tab}"' in text
    expected = {
        "stacks": [f'value="{first}/site"', f'value="{second}/site"'],
        "images": [f'value="{first}/nginx:1.27"', f'value="{second}/busybox:1.37"'],
        "volumes": ["site_data", "otherhost"],
        "networks": ["site_default", "otherhost"],
        "backups": ["nightly", "otherhost"],
        "hosts": [f'value="{first}/{first}"', "28.5.1"],
        "jobs": [f"/machines/{first}/docker/jobs/"],
    }[kind]
    for snippet in expected:
        assert snippet in text, snippet
    assert 'data-live-fleet' in text


async def test_filters_narrow_a_list(client: Any, db_session_factory: Any) -> None:
    await _stored_machine(db_session_factory)

    unused = await client.get("/docker/images?show=unused")
    searched = await client.get("/docker/images?q=nginx")
    custom = await client.get("/docker/networks?show=custom")
    bogus = await client.get("/docker/images?show=nonsense")

    assert "busybox:1.37" in unused.text and "nginx:1.27</code>" not in unused.text
    assert "nginx:1.27" in searched.text and "busybox:1.37" not in searched.text
    assert "site_default" in custom.text and "<code>bridge</code>" not in custom.text
    assert bogus.status_code == 200 and "busybox:1.37" in bogus.text


async def test_a_viewer_sees_the_lists_without_any_action(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    await _stored_machine(db_session_factory)
    await login_as(client, permissions=VIEWER)

    for kind in KINDS:
        response = await client.get(f"/docker/{kind}")
        assert response.status_code == 200, kind
        assert 'name="item"' not in response.text, kind
        assert 'action="/docker/prune"' not in response.text, kind


async def test_a_group_limited_account_sees_only_its_machines(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    from app.db.models.machine_group import MachineGroup

    mine = await _stored_machine(db_session_factory)
    other = await _stored_machine(db_session_factory, name="otherhost")
    async with db_session_factory() as session:
        group = MachineGroup(name="mine")
        session.add(group)
        await session.flush()
        machine = await session.get(Machine, mine)
        assert machine is not None
        machine.group_id = group.id
        await session.commit()
        group_id = group.id
    await login_as(client, permissions=VIEWER, group_ids={group_id})

    response = await client.get("/docker/images")

    assert f"/machines/{mine}/docker" in response.text
    assert f"/machines/{other}/docker" not in response.text


# --- Actions ---------------------------------------------------------------------------


async def test_restarting_stacks_on_two_machines_starts_a_job_on_each(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    first = await _stored_machine(db_session_factory)
    second = await _stored_machine(db_session_factory, name="otherhost")
    csrf = await _csrf(client)

    response = await client.post(
        "/docker/stacks/bulk",
        data={"csrf_token": csrf, "action": "restart",
              "item": [f"{first}/site", f"{second}/site"], "back": "/docker/stacks"},
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith("/docker/stacks")
    for machine_id in (first, second):
        [job] = await jobs_of(db_session_factory, machine_id)
        assert (job.kind, job.target) == (DockerJobKind.STACK_ACTION, "site")
    assert celery_calls.names == [RUN_JOB_TASK, RUN_JOB_TASK]
    assert len(await audit_entries(db_session_factory, "machine.docker.stack.action")) == 2


async def test_one_selected_row_goes_to_its_job(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _stored_machine(db_session_factory)
    csrf = await _csrf(client)

    response = await client.post(
        "/docker/images/bulk",
        data={"csrf_token": csrf, "action": "pull", "item": f"{machine_id}/nginx:1.27"},
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"


async def test_bulk_needs_the_actions_own_permission(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _stored_machine(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER})
    csrf = await _csrf(client)

    update = await client.post(
        "/docker/stacks/bulk",
        data={"csrf_token": csrf, "action": "update", "item": f"{machine_id}/site"},
    )
    unknown = await client.post(
        "/docker/stacks/bulk",
        data={"csrf_token": csrf, "action": "rm -rf", "item": f"{machine_id}/site"},
    )
    no_kind = await client.post(
        "/docker/volumes/bulk",
        data={"csrf_token": csrf, "action": "remove", "item": f"{machine_id}/site_data"},
    )
    no_csrf = await client.post(
        "/docker/stacks/bulk", data={"action": "restart", "item": f"{machine_id}/site"}
    )

    assert update.status_code == 403
    assert unknown.status_code == 400
    assert no_kind.status_code == 404
    assert no_csrf.status_code == 403
    assert await jobs_of(db_session_factory, machine_id) == []


async def test_rows_of_machines_the_account_cant_see_are_skipped(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    from app.db.models.machine_group import MachineGroup

    hidden = await _stored_machine(db_session_factory)
    async with db_session_factory() as session:
        group = MachineGroup(name="elsewhere")
        session.add(group)
        await session.commit()
        group_id = group.id
    await login_as(
        client,
        permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER},
        group_ids={group_id},
    )
    csrf = await _csrf(client)

    await client.post(
        "/docker/stacks/bulk",
        data={"csrf_token": csrf, "action": "restart", "item": f"{hidden}/site"},
    )

    assert await jobs_of(db_session_factory, hidden) == []


async def test_invalid_rows_are_dropped(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _stored_machine(db_session_factory)
    csrf = await _csrf(client)

    response = await client.post(
        "/docker/stacks/bulk",
        data={"csrf_token": csrf, "action": "restart",
              "item": ["not-a-uuid/site", f"{machine_id}/bad name;rm", f"{machine_id}"]},
    )

    assert response.status_code == 303
    assert await jobs_of(db_session_factory, machine_id) == []


async def test_backups_run_across_machines(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    first = await _stored_machine(db_session_factory)
    second = await _stored_machine(db_session_factory, name="otherhost")
    one = await add_backup(db_session_factory, first)
    two = await add_backup(db_session_factory, second)
    csrf = await _csrf(client)

    response = await client.post(
        "/docker/backups/bulk",
        data={"csrf_token": csrf, "action": "check",
              "item": [f"{first}/{one}", f"{second}/{two}", f"{first}/{two}"]},
    )

    assert response.status_code == 303
    assert len(await jobs_of(db_session_factory, first)) == 1
    assert len(await jobs_of(db_session_factory, second)) == 1


async def test_the_fleet_clean_up_runs_once_per_machine(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    first = await _stored_machine(db_session_factory)
    second = await _stored_machine(db_session_factory, name="otherhost")
    csrf = await _csrf(client)

    response = await client.post(
        "/docker/prune",
        data={"csrf_token": csrf, "from": "images", "images": "1", "build_cache": "1"},
    )

    assert response.status_code == 303
    for machine_id in (first, second):
        [job] = await jobs_of(db_session_factory, machine_id)
        assert job.kind == DockerJobKind.PRUNE
    notice = await follow(client, response.headers["location"])
    assert "2" in notice


async def test_the_fleet_clean_up_never_removes_named_volumes(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _stored_machine(db_session_factory)
    csrf = await _csrf(client)

    response = await client.post(
        "/docker/prune",
        data={"csrf_token": csrf, "from": "volumes", "volumes": "1", "all_volumes": "1"},
    )

    assert response.status_code == 303
    assert await jobs_of(db_session_factory, machine_id) == []
    page = await follow(client, response.headers["location"])
    assert "own page" in page


async def test_the_clean_up_needs_updates(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    await _stored_machine(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER})
    csrf = await _csrf(client)

    response = await client.post("/docker/prune", data={"csrf_token": csrf, "images": "1"})

    assert response.status_code == 403


async def test_refresh_reads_only_machines_not_read_just_now(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    fresh = await _stored_machine(db_session_factory)
    stale = await _stored_machine(db_session_factory, name="otherhost")
    async with db_session_factory() as session:
        machine = await session.get(Machine, stale)
        assert machine is not None
        machine.docker_inventory = {
            **(machine.docker_inventory or {}),
            "at": (datetime.now(UTC) - timedelta(hours=2)).isoformat(),
        }
        await session.commit()
    csrf = await _csrf(client)

    response = await client.post("/docker/refresh", data={"csrf_token": csrf, "from": "volumes"})

    assert response.status_code == 303
    assert response.headers["location"].startswith("/docker/volumes?")
    assert celery_calls.names == [REFRESH_TASK]
    assert str(stale) in str(celery_calls[0]) and str(fresh) not in str(celery_calls[0])


# --- REST API -------------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
async def test_every_fleet_list_has_an_api_twin(
    client: Any, db_session_factory: Any, kind: str
) -> None:
    machine_id = await _stored_machine(db_session_factory)
    await add_stack(db_session_factory, machine_id)
    await add_backup(db_session_factory, machine_id)
    await add_job(db_session_factory, machine_id)
    headers = await _api_token(client)

    response = await client.get(f"/api/v1/docker/{kind}", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == len(body[kind]) > 0
    row = body[kind][0]
    assert row["machine_id"] == str(machine_id)
    assert row["key"] == f"{machine_id}/{row['item_id']}"
    if kind == "backups":
        assert "repo-url-password" not in response.text
        assert "restic-password" not in response.text


async def test_the_api_runs_the_same_actions(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _stored_machine(db_session_factory)
    headers = await _api_token(client)

    restarted = await client.post(
        "/api/v1/docker/stacks/bulk",
        json={"action": "restart", "items": [f"{machine_id}/site", "junk"]},
        headers=headers,
    )
    unknown = await client.post(
        "/api/v1/docker/stacks/bulk", json={"action": "explode", "items": []}, headers=headers
    )
    volumes = await client.post(
        "/api/v1/docker/volumes/bulk", json={"action": "remove", "items": []}, headers=headers
    )
    pruned = await client.post(
        "/api/v1/docker/prune", json={"images": True}, headers=headers
    )
    refreshed = await client.post("/api/v1/docker/refresh", json={}, headers=headers)

    assert restarted.status_code == 200
    assert restarted.json()["done"] == 1 and len(restarted.json()["jobs"]) == 1
    assert unknown.status_code == 400
    assert volumes.status_code == 422
    assert pruned.json()["done"] == 1
    # Just read (the snapshot above), so nothing to refresh.
    assert refreshed.json() == {"queued": 0, "machines": 1}


async def test_the_api_checks_each_actions_permission(
    client: Any, db_session_factory: Any, login_as: Any
) -> None:
    machine_id = await _stored_machine(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW}, api_access_enabled=True)
    headers = await _api_token(client)

    bulk = await client.post(
        "/api/v1/docker/hosts/bulk",
        json={"action": "restart", "items": [f"{machine_id}/{machine_id}"]},
        headers=headers,
    )
    prune = await client.post("/api/v1/docker/prune", json={"images": True}, headers=headers)
    anonymous = await client.get("/api/v1/docker/images")

    assert bulk.status_code == 403
    assert prune.status_code == 403
    assert anonymous.status_code == 401
