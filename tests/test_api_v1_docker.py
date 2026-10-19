"""REST API of a machine's Docker tab (`app/web/routes/api_v1_docker.py`):
overview, containers, images, scans, clean-up and jobs. Stacks, projects,
backups and files live in the sibling `test_api_v1_docker_*.py` files,
which reuse the helpers here."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.docker import (
    DockerContainerSetting,
    DockerImageScan,
    DockerJob,
    DockerJobKind,
    DockerJobStatus,
)
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.services import docker_jobs
from tests.test_api_v1_extended import _api_token, _create_machine

INVENTORY = "app.tasks.docker_jobs.docker_inventory"
RUN_JOB = "app.tasks.docker_jobs.run_docker_job"
IMAGE_ID = "sha256:" + "a" * 64
OLD_IMAGE_ID = "sha256:" + "b" * 64

CONTAINERS: list[dict[str, Any]] = [
    {"name": "web", "image": "nginx:1.27", "id": "c0ffee", "compose_project": "shop"},
    {"name": "db", "image": "postgres:17", "id": "deadbeef", "compose_project": "shop"},
    {"name": "dc-app", "image": "debcontrol:1", "id": "f00d", "compose_project": "debcontrol"},
]


def base(machine_id: str) -> str:
    return f"/api/v1/machines/{machine_id}/docker"


async def docker_machine(
    client: AsyncClient,
    db_session_factory: Any,
    headers: dict[str, str],
    name: str = "dock",
    *,
    ready: bool = True,
) -> str:
    """A machine with Docker containers from monitoring and (when `ready`)
    a confirmed host key."""
    machine_id = await _create_machine(client, headers, name)
    async with db_session_factory() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        assert machine is not None
        machine.host_key_fingerprint = "SHA256:test" if ready else None
        machine.docker_status = "ok"
        machine.docker_containers = [dict(c) for c in CONTAINERS]
        machine.docker_image_updates = {"nginx:1.27": "update", "postgres:17": "current"}
        await session.commit()
    return machine_id


async def headers_for(
    client: AsyncClient,
    login_as: Callable[..., Awaitable[Any]],
    permissions: set[Permission],
    username: str = "docker-limited",
    **user_kwargs: Any,
) -> dict[str, str]:
    """An API token of a fresh account with exactly `permissions`. Leaves
    `client`'s cookie on that account; tokens made before stay valid."""
    await login_as(
        client,
        permissions=permissions,
        username=username,
        api_access_enabled=True,
        **user_kwargs,
    )
    return await _api_token(client)


async def add_job(
    db_session_factory: Any,
    machine_id: str,
    *,
    kind: str = DockerJobKind.CONTAINER_UPDATE,
    target: str = "web",
    status: str = DockerJobStatus.SUCCEEDED,
    result: dict[str, Any] | None = None,
    ref_id: uuid.UUID | None = None,
    output: str = "",
) -> uuid.UUID:
    async with db_session_factory() as session:
        job = DockerJob(
            machine_id=uuid.UUID(machine_id),
            kind=kind,
            target=target,
            status=status,
            result=result,
            ref_id=ref_id,
            output=output,
            params={},
        )
        session.add(job)
        await session.commit()
        return job.id


async def audit_actions(db_session_factory: Any) -> list[tuple[str, str]]:
    async with db_session_factory() as session:
        rows = await session.execute(select(AuditLogEntry.action, AuditLogEntry.outcome))
        return [(str(a), str(o)) for a, o in rows.all()]


# --- Overview and containers ----------------------------------------------------


async def test_overview_lists_containers_with_state(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    async with db_session_factory() as session:
        session.add(
            DockerContainerSetting(
                machine_id=uuid.UUID(machine_id),
                name="web",
                auto_update=True,
                vulnerability_gate="high",
            )
        )
        session.add(
            DockerImageScan(
                machine_id=uuid.UUID(machine_id),
                image_id=IMAGE_ID,
                image_ref="nginx:1.27",
                counts={"critical": 1},
            )
        )
        await session.commit()

    response = await client.get(base(machine_id), headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["protected_project"] is None
    by_name = {c["name"]: c for c in body["containers"]}
    assert by_name["web"]["auto_update"] is True
    assert by_name["web"]["vulnerability_gate"] == "high"
    assert by_name["web"]["image_update"] == "update"
    assert by_name["web"]["vulnerabilities"] == {"critical": 1}
    assert by_name["db"]["auto_update"] is False
    assert by_name["db"]["vulnerability_gate"] == "off"
    assert by_name["db"]["vulnerabilities"] is None


async def test_overview_needs_view_and_a_visible_machine(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    missing = await client.get(base(str(uuid.uuid4())), headers=headers)
    assert missing.status_code == 404

    nobody = await headers_for(client, login_as, set(), username="docker-nobody")
    assert (await client.get(base(machine_id), headers=nobody)).status_code == 403

    viewer = await headers_for(client, login_as, {Permission.MACHINE_VIEW})
    assert (await client.get(base(machine_id), headers=viewer)).status_code == 200


async def test_session_cookie_alone_is_not_api_auth(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    response = await client.get(base(machine_id))
    assert response.status_code in (401, 403)


async def test_container_detail_from_inventory(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    celery_calls.result_for[INVENTORY] = {
        "ok": True,
        "inventory": {"containers": [{"name": "web", "image_id": IMAGE_ID, "env": ["A"]}]},
    }
    await add_job(db_session_factory, machine_id, result={"previous_image_id": OLD_IMAGE_ID})

    response = await client.get(f"{base(machine_id)}/containers/web", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["container"]["name"] == "web"
    assert body["rollback_image_id"] == OLD_IMAGE_ID
    assert body["scan"] is None
    assert len(body["jobs"]) == 1
    assert INVENTORY in celery_calls.names

    gone = await client.get(f"{base(machine_id)}/containers/nope", headers=headers)
    assert gone.status_code == 404
    invalid = await client.get(f"{base(machine_id)}/containers/-bad", headers=headers)
    assert invalid.status_code == 404


async def test_container_detail_worker_error_is_502(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    celery_calls.result_for[INVENTORY] = {"ok": False, "error": "ssh down"}
    response = await client.get(f"{base(machine_id)}/containers/web", headers=headers)
    assert response.status_code == 502
    assert "ssh down" in response.json()["detail"]


async def test_container_settings_save_validate_and_permission(
    client, login_as, db_session_factory
):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    url = f"{base(machine_id)}/containers/web/settings"

    ok = await client.put(
        url, json={"auto_update": True, "vulnerability_gate": "critical"}, headers=headers
    )
    assert ok.status_code == 200, ok.text
    overview = (await client.get(base(machine_id), headers=headers)).json()
    web = next(c for c in overview["containers"] if c["name"] == "web")
    assert web["auto_update"] is True
    assert web["vulnerability_gate"] == "critical"
    assert ("machine.docker.container.settings", "success") in await audit_actions(
        db_session_factory
    )

    bad_gate = await client.put(url, json={"vulnerability_gate": "nope"}, headers=headers)
    assert bad_gate.status_code == 400
    bad_type = await client.put(url, json={"auto_update": "maybe"}, headers=headers)
    assert bad_type.status_code == 422

    viewer = await headers_for(client, login_as, {Permission.MACHINE_VIEW})
    assert (await client.put(url, json={}, headers=viewer)).status_code == 403
    power = await headers_for(client, login_as, {Permission.ACTION_POWER}, username="dk-power")
    assert (await client.put(url, json={}, headers=power)).status_code == 403


async def test_container_update_queues_a_job(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    response = await client.post(
        f"{base(machine_id)}/containers/web/update",
        json={"vulnerability_gate": "high"},
        headers=headers,
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert [j["target"] for j in body["jobs"]] == ["web"]
    assert body["jobs"][0]["params"]["gate"] == "high"
    assert body["skipped"] == {}
    assert RUN_JOB in celery_calls.names

    # The same update is already waiting: skipped, not queued twice.
    again = await client.post(f"{base(machine_id)}/containers/web/update", headers=headers)
    assert again.status_code == 202
    assert again.json() == {"jobs": [], "skipped": {"web": "already_queued"}}


async def test_container_update_validation(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    bad_gate = await client.post(
        f"{base(machine_id)}/containers/web/update",
        json={"vulnerability_gate": "bogus"},
        headers=headers,
    )
    assert bad_gate.status_code == 400
    bad_name = await client.post(f"{base(machine_id)}/containers/-x/update", headers=headers)
    assert bad_name.status_code == 400


async def test_container_update_needs_host_key(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers, ready=False)
    response = await client.post(f"{base(machine_id)}/containers/web/update", headers=headers)
    assert response.status_code == 400
    assert "host key" in response.json()["detail"]


async def test_container_update_permission(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    for perms, username in (
        ({Permission.MACHINE_VIEW}, "dk-view"),
        ({Permission.MACHINE_VIEW, Permission.ACTION_POWER}, "dk-power"),
    ):
        limited = await headers_for(client, login_as, perms, username=username)
        for url in ("containers/web/update", "containers/web/rollback"):
            response = await client.post(f"{base(machine_id)}/{url}", headers=limited)
            assert response.status_code == 403, (url, username)
        many = await client.post(
            f"{base(machine_id)}/update", json={"containers": ["web"]}, headers=limited
        )
        assert many.status_code == 403

    updater = await headers_for(
        client, login_as, {Permission.ACTION_UPDATES}, username="dk-updates"
    )
    response = await client.post(f"{base(machine_id)}/containers/web/update", headers=updater)
    assert response.status_code == 202


async def test_container_update_protected_is_skipped_and_audited(
    client, db_session_factory, monkeypatch
):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    async def _protected(db: Any, machine: Any) -> str:
        return "debcontrol"

    monkeypatch.setattr(docker_jobs, "protected_project", _protected)

    response = await client.post(f"{base(machine_id)}/containers/dc-app/update", headers=headers)
    assert response.status_code == 202
    assert response.json() == {"jobs": [], "skipped": {"dc-app": "protected"}}
    assert ("machine.docker.container.update", "denied") in await audit_actions(db_session_factory)
    overview = (await client.get(base(machine_id), headers=headers)).json()
    assert overview["protected_project"] == "debcontrol"


async def test_update_many_by_names_and_scope(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    by_scope = await client.post(
        f"{base(machine_id)}/update", json={"scope": "with_update"}, headers=headers
    )
    assert by_scope.status_code == 202, by_scope.text
    assert [j["target"] for j in by_scope.json()["jobs"]] == ["web"]

    by_name = await client.post(
        f"{base(machine_id)}/update", json={"containers": ["db", "-bad"]}, headers=headers
    )
    assert by_name.status_code == 202
    assert [j["target"] for j in by_name.json()["jobs"]] == ["db"]

    nothing = await client.post(
        f"{base(machine_id)}/update", json={"containers": ["-bad"]}, headers=headers
    )
    assert nothing.status_code == 400

    bad_scope = await client.post(
        f"{base(machine_id)}/update", json={"scope": "all"}, headers=headers
    )
    assert bad_scope.status_code == 422

    too_many = await client.post(
        f"{base(machine_id)}/update", json={"containers": ["c"] * 501}, headers=headers
    )
    assert too_many.status_code == 422


async def test_rollback(client, db_session_factory, monkeypatch):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    url = f"{base(machine_id)}/containers/web/rollback"

    nothing = await client.post(url, headers=headers)
    assert nothing.status_code == 400

    await add_job(db_session_factory, machine_id, result={"previous_image_id": OLD_IMAGE_ID})
    ok = await client.post(url, headers=headers)
    assert ok.status_code == 202, ok.text
    job = ok.json()["job"]
    assert job["kind"] == "container_rollback"
    assert job["params"] == {"image_id": OLD_IMAGE_ID}

    # Already waiting: 409.
    again = await client.post(url, headers=headers)
    assert again.status_code == 409

    async def _protected(db: Any, machine: Any) -> str:
        return "shop"

    monkeypatch.setattr(docker_jobs, "protected_project", _protected)
    protected = await client.post(url, headers=headers)
    assert protected.status_code == 409
    assert "debcontrol" in protected.json()["detail"]
    assert ("machine.docker.container.rollback", "denied") in await audit_actions(
        db_session_factory
    )


# --- Images, scans, clean-up ------------------------------------------------------


async def test_images_with_scan_counts(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    async with db_session_factory() as session:
        session.add(
            DockerImageScan(
                machine_id=uuid.UUID(machine_id),
                image_id=IMAGE_ID,
                image_ref="nginx:1.27",
                counts={"high": 2},
                vulnerabilities=[{"id": "CVE-1"}],
            )
        )
        await session.commit()
    celery_calls.result_for[INVENTORY] = {
        "ok": True,
        "inventory": {
            "images": [{"id": IMAGE_ID}, {"id": OLD_IMAGE_ID}],
            "df": {"images": 1},
        },
    }
    response = await client.get(f"{base(machine_id)}/images", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["disk_usage"] == {"images": 1}
    assert body["images"][0]["vulnerabilities"] == {"high": 2}
    assert body["images"][1]["vulnerabilities"] is None

    vulns = await client.get(
        f"{base(machine_id)}/images/{IMAGE_ID}/vulnerabilities", headers=headers
    )
    assert vulns.status_code == 200
    assert vulns.json()["vulnerabilities"] == [{"id": "CVE-1"}]

    none = await client.get(
        f"{base(machine_id)}/images/{OLD_IMAGE_ID}/vulnerabilities", headers=headers
    )
    assert none.status_code == 404
    invalid = await client.get(f"{base(machine_id)}/images/xyz/vulnerabilities", headers=headers)
    assert invalid.status_code == 404


async def test_volumes_and_networks(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    celery_calls.result_for[INVENTORY] = {
        "ok": True,
        "inventory": {"volumes": [{"name": "data"}], "networks": [{"name": "bridge"}]},
    }
    volumes = await client.get(f"{base(machine_id)}/volumes?sizes=true", headers=headers)
    assert volumes.status_code == 200
    assert volumes.json() == {"volumes": [{"name": "data"}]}
    sections = [args[1] for name, args, _kw in celery_calls if name == INVENTORY]
    assert "volume_sizes" in sections[-1]

    networks = await client.get(f"{base(machine_id)}/networks", headers=headers)
    assert networks.json() == {"networks": [{"name": "bridge"}]}


async def test_network_detail(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    celery_calls.result_for[INVENTORY] = {
        "ok": True,
        "inventory": {"network_details": [{"name": "site_default", "subnets": []}]},
    }
    found = await client.get(f"{base(machine_id)}/networks/site_default", headers=headers)
    assert found.status_code == 200
    assert found.json() == {"network": {"name": "site_default", "subnets": []}}
    sections = [args[1] for name, args, _kw in celery_calls if name == INVENTORY]
    assert sections[-1] == ["network_inspect"]

    missing = await client.get(f"{base(machine_id)}/networks/other", headers=headers)
    assert missing.status_code == 404
    invalid = await client.get(f"{base(machine_id)}/networks/bad;name", headers=headers)
    assert invalid.status_code == 404


async def test_scan_images(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    url = f"{base(machine_id)}/images/scan"

    one = await client.post(
        url, json={"image": "nginx:1.27", "image_id": IMAGE_ID}, headers=headers
    )
    assert one.status_code == 202, one.text
    assert one.json()["job"]["target"] == "nginx:1.27"

    scope = await client.post(url, json={}, headers=headers)
    assert scope.status_code == 202
    assert scope.json()["job"]["target"] == "scope:in_use"
    assert ("machine.docker.images.scan", "success") in await audit_actions(db_session_factory)

    twice = await client.post(url, json={}, headers=headers)
    assert twice.status_code == 409

    bad_image = await client.post(
        url, json={"image": "nginx;rm", "image_id": IMAGE_ID}, headers=headers
    )
    assert bad_image.status_code == 400
    bad_scope = await client.post(url, json={"scope": "bogus"}, headers=headers)
    assert bad_scope.status_code == 400

    viewer = await headers_for(client, login_as, {Permission.MACHINE_VIEW})
    assert (await client.post(url, json={}, headers=viewer)).status_code == 403


async def test_prune_confirm_and_permission(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers, name="dock-prune")
    url = f"{base(machine_id)}/prune"

    nothing = await client.post(url, json={}, headers=headers)
    assert nothing.status_code == 400

    unconfirmed = await client.post(
        url, json={"volumes": True, "all_volumes": True, "confirm": "wrong"}, headers=headers
    )
    assert unconfirmed.status_code == 400
    assert ("machine.docker.prune", "denied") in await audit_actions(db_session_factory)

    without_volumes = await client.post(
        url, json={"all_volumes": True, "images": True, "confirm": "dock-prune"}, headers=headers
    )
    assert without_volumes.status_code == 400

    confirmed = await client.post(
        url,
        json={"volumes": True, "all_volumes": True, "confirm": " dock-prune "},
        headers=headers,
    )
    assert confirmed.status_code == 202, confirmed.text
    assert confirmed.json()["job"]["params"]["all_volumes"] is True

    busy = await client.post(url, json={"images": True}, headers=headers)
    assert busy.status_code == 409

    bad_type = await client.post(url, json={"images": "lots"}, headers=headers)
    assert bad_type.status_code == 422

    viewer = await headers_for(client, login_as, {Permission.MACHINE_VIEW})
    assert (await client.post(url, json={"images": True}, headers=viewer)).status_code == 403


# --- Jobs ---------------------------------------------------------------------------


async def test_jobs_list_and_detail_scoped_to_machine(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    other_id = await docker_machine(client, db_session_factory, headers, name="dock-other")
    job_id = await add_job(db_session_factory, machine_id, output="pulled")
    other_job = await add_job(db_session_factory, other_id)

    listed = await client.get(f"{base(machine_id)}/jobs", headers=headers)
    assert listed.status_code == 200
    assert [j["id"] for j in listed.json()] == [str(job_id)]
    assert "output" not in listed.json()[0]

    detail = await client.get(f"{base(machine_id)}/jobs/{job_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["output"] == "pulled"

    leak = await client.get(f"{base(machine_id)}/jobs/{other_job}", headers=headers)
    assert leak.status_code == 404
    bad = await client.get(f"{base(machine_id)}/jobs/not-a-uuid", headers=headers)
    assert bad.status_code == 422


async def test_machine_outside_the_tokens_groups_is_404(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    job_id = await add_job(db_session_factory, machine_id)
    async with db_session_factory() as session:
        group = MachineGroup(name="elsewhere")
        session.add(group)
        await session.commit()
        group_id = group.id
    scoped = await headers_for(
        client,
        login_as,
        set(Permission),
        username="dk-scoped",
        group_ids={group_id},
    )
    for url in ("", "/jobs", f"/jobs/{job_id}", "/stacks", "/backups"):
        response = await client.get(f"{base(machine_id)}{url}", headers=scoped)
        assert response.status_code == 404, url
    update = await client.post(f"{base(machine_id)}/containers/web/update", headers=scoped)
    assert update.status_code == 404
    action = await client.post(f"{base(machine_id)}/projects/shop/stop", headers=scoped)
    assert action.status_code == 404


async def test_rollback_with_unusable_previous_image_is_400(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    await add_job(db_session_factory, machine_id, result={"previous_image_id": "nginx:old"})
    response = await client.post(f"{base(machine_id)}/containers/web/rollback", headers=headers)
    assert response.status_code == 400
