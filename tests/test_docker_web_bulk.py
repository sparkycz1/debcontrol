"""The containers page at a glance and its buttons for the selected rows
(Docker upgrade #1): state tiles, web/image links, compact vulnerability
counts, and `POST .../docker/containers/bulk` — each action behind the
same permission as doing it to one container — plus its REST twin."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import DockerJobKind
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.services import docker_jobs
from tests.test_api_v1_docker import base, docker_machine, headers_for
from tests.test_api_v1_extended import _api_token
from tests.test_docker_web_support import (
    RUN_JOB_TASK,
    VIEWER,
    add_scan,
    audit_entries,
    csrf_token,
    follow,
    jobs_of,
    make_docker_machine,
)

ACTION_TASK = "app.tasks.jobs.run_container_action"
POWER_ONLY = frozenset({Permission.MACHINE_VIEW, Permission.ACTION_POWER})
UPDATES_ONLY = frozenset({Permission.MACHINE_VIEW, Permission.ACTION_UPDATES})


async def _with_links(db_session_factory: Any, machine_id: uuid.UUID) -> None:
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        containers = [dict(c) for c in machine.docker_containers or []]
        containers[0]["link_labels"] = {
            "traefik.http.routers.web.rule": "Host(`shop.example.com`)",
            "org.opencontainers.image.source": "https://github.com/nginx/docker-nginx",
        }
        machine.docker_containers = containers
        await session.commit()


# --- The page ---------------------------------------------------------------------


async def test_page_shows_state_tiles_links_and_bulk_buttons(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    await _with_links(db_session_factory, machine_id)
    await add_scan(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/docker")

    assert response.status_code == 200
    html = response.text
    # Tiles: everything, one running, one stopped — none for empty groups.
    assert 'data-state-tiles="containers-table"' in html
    assert 'class="state-tile state-tile-running"' in html
    assert 'class="state-tile state-tile-exited"' in html
    assert "state-tile-paused" not in html
    assert 'data-row-state="running"' in html
    assert 'data-row-state="exited"' in html
    # The proxy name comes before the published port; both open without
    # an opener.
    assert 'rel="noopener noreferrer"' in html
    assert html.index('href="https://shop.example.com"') < html.index('href="http://10.20.0.5:80"')
    # The image has an update, so its registry and release notes are linked.
    assert 'href="https://hub.docker.com/_/nginx"' in html
    assert 'href="https://github.com/nginx/docker-nginx/releases"' in html
    assert 'class="severity-compact"' in html
    # The selected rows' buttons and the remembered table.
    assert f'action="/machines/{machine_id}/docker/containers/bulk"' in html
    for action in ("start", "stop", "restart", "update", "scan", "remove"):
        assert f'name="action" value="{action}"' in html
    assert 'data-remember="docker-containers"' in html
    assert "js/docker-table.js" in html


async def test_a_viewer_sees_no_checkboxes_or_buttons(client, login_as, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(client, permissions=VIEWER)

    html = (await client.get(f"/machines/{machine_id}/docker")).text

    assert "containers-bulk" not in html
    assert 'name="action"' not in html


async def test_power_only_sees_power_buttons(client, login_as, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(client, permissions=POWER_ONLY)

    html = (await client.get(f"/machines/{machine_id}/docker")).text

    assert 'name="action" value="stop"' in html
    assert 'name="action" value="remove"' not in html
    assert 'name="action" value="scan"' not in html


# --- POST .../containers/bulk ----------------------------------------------------------


async def test_bulk_needs_a_csrf_token(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"action": "stop", "container": "web"},
    )

    assert response.status_code == 403
    assert celery_calls == []


@pytest.mark.parametrize(
    ("permissions", "action"),
    [
        (VIEWER, "start"),
        (UPDATES_ONLY, "stop"),
        (UPDATES_ONLY, "restart"),
        (POWER_ONLY, "remove"),
        (POWER_ONLY, "scan"),
        (POWER_ONLY, "update"),
    ],
)
async def test_bulk_needs_the_actions_own_permission(
    client, login_as, db_session_factory, celery_calls, permissions, action
):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(client, permissions=permissions)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"csrf_token": csrf, "action": action, "container": "web"},
    )

    assert response.status_code == 403
    assert celery_calls == []
    assert await jobs_of(db_session_factory, machine_id) == []


async def test_bulk_rejects_an_unknown_action(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"csrf_token": csrf, "action": "kill", "container": "web"},
    )

    assert response.status_code == 400
    assert celery_calls == []


async def test_bulk_stop_runs_one_command_for_all_and_audits_each(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"csrf_token": csrf, "action": "stop", "container": ["web", "worker", "x;id"]},
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(f"/machines/{machine_id}/docker?notice=")
    assert celery_calls.names == [ACTION_TASK]
    assert celery_calls[0][2] == {"action": "stop", "containers": ["web", "worker"]}
    entries = await audit_entries(db_session_factory, "machine.container.stop")
    assert [(e.details or {}).get("container") for e in entries] == ["web", "worker"]
    assert all(e.outcome == AuditOutcome.SUCCESS for e in entries)
    assert "Stopped 2 container(s)." in await follow(client, response.headers["location"])


async def test_bulk_remove_reports_dockers_refusal(client, db_session_factory, celery_calls):
    celery_calls.result_for[ACTION_TASK] = {
        "ok": False,
        "error": "cannot remove container: container is running",
    }
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"csrf_token": csrf, "action": "remove", "container": "web"},
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    [entry] = await audit_entries(db_session_factory, "machine.container.remove")
    assert entry.outcome == AuditOutcome.FAILURE
    assert "container is running" in await follow(client, response.headers["location"])


async def test_bulk_leaves_out_debcontrols_own_containers_except_for_start(
    client, db_session_factory, celery_calls, monkeypatch
):
    async def _own_project(db, machine):
        return "site"

    monkeypatch.setattr("app.services.docker_jobs.protected_project", _own_project)
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    stop = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"csrf_token": csrf, "action": "stop", "container": ["web", "worker"]},
    )
    start = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"csrf_token": csrf, "action": "start", "container": ["web"]},
    )

    assert stop.status_code == start.status_code == 303
    assert "error=" in stop.headers["location"]
    assert [call[2]["containers"] for call in celery_calls] == [["worker"], ["web"]]
    denied = [
        e
        for e in await audit_entries(db_session_factory, "machine.container.stop")
        if e.outcome == AuditOutcome.DENIED
    ]
    assert [e.details for e in denied] == [{"container": "web", "reason": "protected"}]


async def test_bulk_scan_queues_one_scan_of_the_selected_images(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"csrf_token": csrf, "action": "scan", "container": ["web", "worker"]},
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"
    assert job.kind == DockerJobKind.IMAGE_SCAN
    assert job.params == {"refs": ["nginx:1.27", "redis:7"]}
    assert celery_calls.names == [RUN_JOB_TASK]
    assert await audit_entries(db_session_factory, "machine.docker.images.scan")


async def test_bulk_update_queues_one_update_per_container(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"csrf_token": csrf, "action": "update", "container": ["web", "worker"]},
    )

    jobs = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert response.headers["location"].startswith(f"/machines/{machine_id}/docker/jobs?")
    assert sorted(j.target for j in jobs) == ["web", "worker"]
    assert {j.kind for j in jobs} == {DockerJobKind.CONTAINER_UPDATE}


async def test_bulk_with_nothing_selected_says_so(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"csrf_token": csrf, "action": "restart"},
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls == []


# --- REST API ---------------------------------------------------------------------------


async def test_api_overview_has_state_groups_and_links(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    body = (await client.get(base(machine_id), headers=headers)).json()

    assert body["state_counts"]["created"] == 3  # the seeded rows carry no state
    web = next(c for c in body["containers"] if c["name"] == "web")
    assert web["row_state"] == "created"
    assert web["web_links"] == []
    assert web["image_links"]["registry_url"] == "https://hub.docker.com/_/nginx"


async def test_api_bulk_restart_and_permissions(
    client, login_as, db_session_factory, celery_calls
):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    response = await client.post(
        f"{base(machine_id)}/containers/bulk",
        headers=headers,
        json={"action": "restart", "containers": ["web", "db"]},
    )

    assert response.status_code == 200
    assert response.json()["containers"] == ["web", "db"]
    assert celery_calls[-1][2] == {"action": "restart", "containers": ["web", "db"]}

    power = await headers_for(client, login_as, {Permission.MACHINE_VIEW, Permission.ACTION_POWER})
    refused = await client.post(
        f"{base(machine_id)}/containers/bulk",
        headers=power,
        json={"action": "remove", "containers": ["web"]},
    )
    assert refused.status_code == 403


async def test_api_bulk_refuses_only_protected_containers(
    client, db_session_factory, celery_calls, monkeypatch
):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    async def _protected(db, machine):
        return "debcontrol"

    monkeypatch.setattr(docker_jobs, "protected_project", _protected)

    response = await client.post(
        f"{base(machine_id)}/containers/bulk",
        headers=headers,
        json={"action": "stop", "containers": ["dc-app"]},
    )

    assert response.status_code == 409
    assert celery_calls.names == []


async def test_api_scan_of_references(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    response = await client.post(
        f"{base(machine_id)}/images/scan",
        headers=headers,
        json={"refs": ["nginx:1.27", "bad ref!"]},
    )

    assert response.status_code == 202
    assert response.json()["job"]["params"] == {"refs": ["nginx:1.27"]}
