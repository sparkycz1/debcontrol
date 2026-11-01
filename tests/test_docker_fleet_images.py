"""Docker new features, part 1: every container of the fleet in one list
(`app.services.docker_fleet`, Docker -> Containers and its REST twin),
actions on one image (`app.ssh.docker_images`: pull, tag, remove, details
and layers) and a container's limits changed in place
(`app.ssh.docker_resources`, `docker update`).

As everywhere else, the underscore-prefixed coroutines are called
directly, never the Celery wrappers."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from app.db.models.docker import DockerJob, DockerJobKind, DockerJobStatus
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.services import docker_fleet, docker_jobs
from app.ssh import docker_images, docker_resources
from app.ssh.docker_cli import DockerCommandError
from app.tasks import docker_jobs as tasks
from tests.test_docker_tasks_jobs import (
    FakeMachine,
    _add,
    _get,
    _job,
    _machine,
    install_fake_machine,
)
from tests.test_docker_web_support import (
    IMAGE_ID,
    RUN_JOB_TASK,
    audit_entries,
    csrf_token,
    follow,
    jobs_of,
    make_docker_machine,
)
from tests.test_update_history import _api_token

IMAGE_OP_TASK = "app.tasks.docker_jobs.docker_image_op"
RESOURCES_TASK = "app.tasks.docker_jobs.docker_container_resources"
CONTAINER_ACTION_TASK = "app.tasks.jobs.run_container_action"


@pytest.fixture
def machine_shell(monkeypatch: pytest.MonkeyPatch, db_session_factory: Any) -> FakeMachine:
    return install_fake_machine(monkeypatch, db_session_factory)


@pytest.fixture(autouse=True)
def _fresh_presence_cache() -> None:
    docker_fleet.reset_presence_cache()


# --- The fleet list ------------------------------------------------------------------


async def test_fleet_page_lists_every_machines_containers(
    client: Any, db_session_factory: Any
) -> None:
    first = await make_docker_machine(db_session_factory)
    second = await make_docker_machine(db_session_factory, name="otherhost")

    response = await client.get("/docker/containers")

    assert response.status_code == 200
    assert f'value="{first}/web"' in response.text
    assert f'value="{second}/worker"' in response.text
    # The header's Docker entry is there once some machine has Docker.
    assert 'href="/docker"' in response.text


async def test_docker_entry_redirects_to_containers(client: Any) -> None:
    response = await client.get("/docker")

    assert response.status_code == 303
    assert response.headers["location"] == "/docker/containers"


async def test_fleet_filters_sort_and_page(
    client: Any, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_docker_machine(db_session_factory)
    await make_docker_machine(db_session_factory, name="otherhost")
    headers = await _api_token(client)

    running = await client.get("/api/v1/docker/containers?state=running", headers=headers)
    updates = await client.get("/api/v1/docker/containers?update=true", headers=headers)
    text = await client.get("/api/v1/docker/containers?q=redis", headers=headers)
    stack = await client.get("/api/v1/docker/containers?stack=site", headers=headers)
    by_name = await client.get(
        "/api/v1/docker/containers?sort=name&desc=true", headers=headers
    )
    monkeypatch.setattr(docker_fleet, "PAGE_SIZE", 3)
    second_page = await client.get("/api/v1/docker/containers?page=2", headers=headers)

    assert {c["name"] for c in running.json()["containers"]} == {"web"}
    assert running.json()["state_counts"]["exited"] == 2  # counts ignore the state filter
    assert {c["image_update"] for c in updates.json()["containers"]} == {"update"}
    assert {c["name"] for c in text.json()["containers"]} == {"worker"}
    assert {c["compose_project"] for c in stack.json()["containers"]} == {"site"}
    assert [c["name"] for c in by_name.json()["containers"]][:2] == ["worker", "worker"]
    assert second_page.json()["pages"] == 2
    assert len(second_page.json()["containers"]) == 1


async def test_fleet_shows_only_machines_the_account_may_see(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    async with db_session_factory() as session:
        group = MachineGroup(name="prod")
        session.add(group)
        await session.commit()
        group_id = group.id
    visible = await make_docker_machine(db_session_factory)
    hidden = await make_docker_machine(db_session_factory, name="hiddenhost")
    async with db_session_factory() as session:
        from app.db.models.machine import Machine

        row = await session.get(Machine, visible)
        assert row is not None
        row.group_id = group_id
        await session.commit()
    await login_as(client, permissions={Permission.MACHINE_VIEW}, group_ids={group_id})

    response = await client.get("/docker/containers")

    assert response.status_code == 200
    assert "dockerhost" in response.text
    assert "hiddenhost" not in response.text
    assert str(hidden) not in response.text


async def test_fleet_bulk_runs_per_machine_and_audits_each(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    first = await make_docker_machine(db_session_factory)
    second = await make_docker_machine(db_session_factory, name="otherhost")
    await client.get("/docker/containers")
    csrf = client.cookies.get("csrftoken")

    response = await client.post(
        "/docker/containers/bulk",
        data={
            "csrf_token": csrf,
            "action": "restart",
            "container": [f"{first}/web", f"{second}/web", "not-a-key", f"{uuid.uuid4()}/x"],
            "back": "https://evil.example/",
        },
    )

    calls = [kw for name, _a, kw in celery_calls if name == CONTAINER_ACTION_TASK]
    assert response.status_code == 303
    assert response.headers["location"].startswith("/docker/containers")
    assert calls == [
        {"action": "restart", "containers": ["web"]},
        {"action": "restart", "containers": ["web"]},
    ]
    assert len(await audit_entries(db_session_factory, "machine.container.restart")) == 2


async def test_fleet_bulk_refuses_remove_and_checks_permission(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    await client.get("/docker/containers")
    csrf = client.cookies.get("csrftoken")
    data = {"csrf_token": csrf, "container": [f"{machine_id}/worker"]}

    remove = await client.post("/docker/containers/bulk", data={**data, "action": "remove"})
    no_csrf = await client.post(
        "/docker/containers/bulk", data={"action": "start", "container": data["container"]}
    )
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER})
    update = await client.post("/docker/containers/bulk", data={**data, "action": "update"})

    assert remove.status_code == 400
    assert no_csrf.status_code == 403
    assert update.status_code == 403
    assert not [c for c in celery_calls if c[0] in (CONTAINER_ACTION_TASK, RUN_JOB_TASK)]


async def test_fleet_bulk_api_updates_and_reports_unknown_machines(
    client: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    headers = await _api_token(client)
    missing = uuid.uuid4()

    response = await client.post(
        "/api/v1/docker/containers/bulk",
        headers=headers,
        json={"action": "update", "containers": [f"{machine_id}/web", f"{missing}/web"]},
    )

    body = response.json()
    assert response.status_code == 200, response.text
    assert body["done"] == 1
    assert body["errors"] == {str(missing): "Machine not found."}
    [job] = await jobs_of(db_session_factory, machine_id)
    assert job.kind == DockerJobKind.CONTAINER_UPDATE and job.target == "web"


def test_parse_keys_drops_bad_values() -> None:
    machine_id = uuid.uuid4()

    grouped = docker_fleet.parse_keys(
        [
            f"{machine_id}/web",
            f"{machine_id}/web",
            f"{machine_id}/db",
            "x/web",
            "nokey",
            f"{machine_id}/",
        ]
    )

    assert grouped == {machine_id: ["web", "db"]}


def test_fleet_filter_parse_ignores_unknown_values() -> None:
    flt = docker_fleet.FleetFilter.parse(
        state="bogus", sort="evil", group="nope", vulns="x", page=-3
    )

    assert flt.state == "" and flt.sort == "machine" and flt.group_id is None
    assert flt.vulns == "" and flt.page == 1


# --- One image -----------------------------------------------------------------------


def test_image_commands_quote_and_validate() -> None:
    assert docker_images.build_remove_command("nginx:1.27") == "$D image rm nginx:1.27"
    assert "--force" not in docker_images.build_remove_command(IMAGE_ID)
    assert docker_images.build_tag_command("nginx:1.27", "registry.test/nginx:prod") == (
        "$D tag nginx:1.27 registry.test/nginx:prod"
    )
    for bad in ("x; rm -rf /", IMAGE_ID, "nginx@sha256:" + "a" * 64):
        with pytest.raises(DockerCommandError):
            docker_images.build_tag_command("nginx:1.27", bad)
    with pytest.raises(DockerCommandError):
        docker_images.build_remove_command("$(reboot)")
    with pytest.raises(DockerCommandError):
        docker_images.build_pull_script(IMAGE_ID)
    assert docker_images.parse_pulled_id(f"pulling\n@@DC_IMAGE_ID {IMAGE_ID}\n") == IMAGE_ID
    assert docker_images.parse_pulled_id("@@DC_IMAGE_ID garbage\n") is None


def test_image_details_leave_out_the_environment() -> None:
    history = "\n".join(
        json.dumps(row)
        for row in (
            {"ID": "<missing>", "CreatedAt": "2026-10-01T10:00:00Z",
             "CreatedBy": "/bin/sh -c #(nop) CMD [\"nginx\"]", "Size": "0B"},
            {"ID": "sha256:abc", "CreatedAt": "2026-10-01T09:00:00Z",
             "CreatedBy": "RUN apt-get install nginx", "Size": "52.4MB"},
        )
    )
    inspect = json.dumps([{
        "Id": IMAGE_ID, "RepoTags": ["nginx:1.27"], "RepoDigests": [],
        "Created": "2026-10-01T10:00:00Z", "Architecture": "amd64", "Os": "linux",
        "Size": 190_000_000,
        "Config": {"Env": ["DB_PASSWORD=hunter2"], "Cmd": ["nginx", "-g", "daemon off;"],
                   "ExposedPorts": {"80/tcp": {}}, "Labels": {"a": "b"}},
    }])

    details = docker_images.parse_details(f"{history}\n@@DC_INSPECT\n{inspect}")

    assert details is not None
    data = details.as_dict()
    assert "hunter2" not in json.dumps(data)
    assert data["tags"] == ["nginx:1.27"] and data["exposed_ports"] == ["80/tcp"]
    assert data["command"] == "nginx -g daemon off;"
    assert [layer["id"] for layer in data["layers"]] == ["", "sha256:abc"]
    assert data["layers"][1]["size_bytes"] > 50_000_000
    assert docker_images.parse_details("no marker") is None


async def test_pull_route_queues_a_job_and_audits(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    url = f"/machines/{machine_id}/docker/images/pull"

    bad = await client.post(url, data={"csrf_token": csrf, "ref": "x; reboot"})
    good = await client.post(url, data={"csrf_token": csrf, "ref": "nginx:1.28"})

    [job] = await jobs_of(db_session_factory, machine_id)
    assert bad.status_code == 303 and "/docker/images" in bad.headers["location"]
    assert good.status_code == 303 and str(job.id) in good.headers["location"]
    assert job.kind == DockerJobKind.IMAGE_PULL and job.target == "nginx:1.28"
    assert (RUN_JOB_TASK, (str(job.id),), {}) in list(celery_calls)
    [entry] = await audit_entries(db_session_factory, "machine.docker.image.pull")
    assert (entry.details or {})["image"] == "nginx:1.28"


async def test_the_pull_job_records_the_pulled_image(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    job = _job(machine, DockerJobKind.IMAGE_PULL, "nginx:1.28")
    await _add(db_session_factory, machine, job)
    machine_shell.finishes(f"1.28: Pulling from library/nginx\n@@DC_IMAGE_ID {IMAGE_ID}\n")

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SUCCEEDED
    assert stored.result["image_id"] == IMAGE_ID
    assert "$D pull nginx:1.28" in machine_shell.started[0][1]
    assert docker_jobs.phase_cancellable(DockerJobKind.IMAGE_PULL, "run")


async def test_remove_and_tag_routes_run_the_quick_task(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    base = f"/machines/{machine_id}/docker/images"

    removed = await client.post(f"{base}/remove", data={"csrf_token": csrf, "image": "redis:7"})
    tagged = await client.post(
        f"{base}/tag", data={"csrf_token": csrf, "image": IMAGE_ID, "new_tag": "nginx:prod"}
    )
    bad_tag = await client.post(
        f"{base}/tag", data={"csrf_token": csrf, "image": IMAGE_ID, "new_tag": "a b"}
    )

    ops = [args for name, args, _kw in celery_calls if name == IMAGE_OP_TASK]
    assert removed.status_code == tagged.status_code == bad_tag.status_code == 303
    assert ops == [
        (str(machine_id), "remove", "redis:7", ""),
        (str(machine_id), "tag", IMAGE_ID, "nginx:prod"),
    ]
    assert len(await audit_entries(db_session_factory, "machine.docker.image.remove")) == 1
    assert len(await audit_entries(db_session_factory, "machine.docker.image.tag")) == 1


async def test_a_failed_remove_shows_dockers_answer_and_is_audited_as_failed(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    celery_calls.result_for[IMAGE_OP_TASK] = {
        "ok": False, "error": "image is being used by running container",
    }

    response = await client.post(
        f"/machines/{machine_id}/docker/images/remove",
        data={"csrf_token": csrf, "image": "nginx:1.27"},
    )

    page = await follow(client, response.headers["location"])
    assert "image is being used by running container" in page
    [entry] = await audit_entries(db_session_factory, "machine.docker.image.remove")
    assert entry.outcome == "failure"


async def test_image_actions_need_action_updates(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER})
    base = f"/machines/{machine_id}/docker/images"

    for path, data in (
        ("pull", {"ref": "nginx:1"}),
        ("remove", {"image": "nginx:1"}),
        ("tag", {"image": "nginx:1", "new_tag": "x:1"}),
    ):
        response = await client.post(f"{base}/{path}", data={"csrf_token": csrf, **data})
        assert response.status_code == 403, path
    assert not [c for c in celery_calls if c[0] in (IMAGE_OP_TASK, RUN_JOB_TASK)]


async def test_image_page_and_panel(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[IMAGE_OP_TASK] = {
        "ok": True,
        "details": {
            "id": IMAGE_ID, "tags": ["nginx:1.27"], "digests": [],
            "created": "2026-10-01T10:00:00Z",
            "architecture": "amd64", "os": "linux", "size_bytes": 1000, "user": "", "workdir": "",
            "entrypoint": "", "command": "nginx", "exposed_ports": [], "labels": {},
            "layers": [
                {"id": "", "created": "", "created_by": "RUN make", "size_bytes": 10,
                 "comment": ""}
            ],
        },
    }

    page = await client.get(f"/machines/{machine_id}/docker/images/{IMAGE_ID}?ref=nginx:1.27")
    panel = await client.get(f"/machines/{machine_id}/docker/images/{IMAGE_ID}/panel")
    missing = await client.get(f"/machines/{machine_id}/docker/images/not-an-id")

    assert page.status_code == 200
    assert "Image nginx:1.27" in page.text
    assert panel.status_code == 200
    assert "RUN make" in panel.text
    # nginx:1.27 runs in "web", so it offers no Remove.
    assert "/images/remove" not in panel.text
    assert 'href="/machines/' in panel.text and "/containers/web" in panel.text
    assert missing.status_code == 404


async def test_image_api(client: Any, db_session_factory: Any, celery_calls: Any) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    headers = await _api_token(client)
    base = f"/api/v1/machines/{machine_id}/docker/images"

    pulled = await client.post(f"{base}/pull", headers=headers, json={"ref": "redis:8"})
    tagged = await client.post(
        f"{base}/tag", headers=headers, json={"image": "redis:8", "tag": "redis:mine"}
    )
    bad = await client.post(
        f"{base}/tag", headers=headers, json={"image": "redis:8", "tag": IMAGE_ID}
    )
    removed = await client.post(f"{base}/remove", headers=headers, json={"image": "redis:mine"})

    assert pulled.status_code == 202, pulled.text
    assert pulled.json()["job"]["kind"] == "image_pull"
    assert tagged.status_code == 200 and removed.status_code == 200
    assert bad.status_code == 400


# --- Container limits ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [("512m", 512 * 1024**2), ("1.5g", int(1.5 * 1024**3)), ("2 GiB", 2 * 1024**3), ("", None)],
)
def test_parse_memory(text: str, expected: int | None) -> None:
    assert docker_resources.parse_memory(text) == expected


@pytest.mark.parametrize("text", ["1k", "lots", "-5m", "5m; reboot"])
def test_parse_memory_refuses(text: str) -> None:
    with pytest.raises(DockerCommandError):
        docker_resources.parse_memory(text)


def test_update_command() -> None:
    change = docker_resources.ResourceChange.parse(
        memory="512m", cpus="1,5", restart_policy="on-failure", max_retries="3"
    )

    command = docker_resources.build_update_command("web", change)

    assert command == (
        "$D update --memory 536870912 --memory-swap 1073741824 --cpus 1.5 "
        "--restart on-failure:3 web"
    )
    assert docker_resources.ResourceChange.from_dict(change.as_dict()) == change
    with pytest.raises(DockerCommandError):
        docker_resources.build_update_command("web", docker_resources.ResourceChange())
    with pytest.raises(DockerCommandError):
        docker_resources.ResourceChange.parse(restart_policy="sometimes")
    with pytest.raises(DockerCommandError):
        docker_resources.ResourceChange.from_dict({"restart_policy": "x; reboot"})


async def test_resources_route_runs_docker_update_and_audits(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    url = f"/machines/{machine_id}/docker/containers/web/resources"

    empty = await client.post(url, data={"csrf_token": csrf})
    bad = await client.post(url, data={"csrf_token": csrf, "memory": "lots"})
    good = await client.post(url, data={"csrf_token": csrf, "memory": "256m", "cpus": "0"})

    calls = [args for name, args, _kw in celery_calls if name == RESOURCES_TASK]
    assert empty.status_code == bad.status_code == good.status_code == 303
    assert calls == [(str(machine_id), "web", {"memory_bytes": 256 * 1024**2, "cpus": 0.0})]
    [entry] = await audit_entries(db_session_factory, "machine.container.resources")
    assert (entry.details or {})["memory_bytes"] == 256 * 1024**2


async def test_resources_refuse_debcontrols_own_container(
    client: Any, db_session_factory: Any, celery_calls: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    async def protected(*_args: Any) -> str:
        return "site"

    monkeypatch.setattr(docker_jobs, "protected_project", protected)
    headers = await _api_token(client)

    web = await client.post(
        f"/machines/{machine_id}/docker/containers/web/resources",
        data={"csrf_token": csrf, "memory": "256m"},
    )
    api = await client.post(
        f"/api/v1/machines/{machine_id}/docker/containers/web/resources",
        headers=headers,
        json={"memory": "256m"},
    )

    assert web.status_code == 303
    assert api.status_code == 409
    assert not [c for c in celery_calls if c[0] == RESOURCES_TASK]
    entries = await audit_entries(db_session_factory, "machine.container.resources")
    assert [e.outcome for e in entries] == ["denied", "denied"]


async def test_resources_api(client: Any, db_session_factory: Any, celery_calls: Any) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    headers = await _api_token(client)
    url = f"/api/v1/machines/{machine_id}/docker/containers/web/resources"

    ok = await client.post(url, headers=headers, json={"cpus": 2, "restart_policy": "always"})
    bad = await client.post(url, headers=headers, json={"memory": "1k"})

    assert ok.status_code == 200, ok.text
    assert ok.json()["changed"] == {"cpus": 2.0, "restart_policy": "always"}
    assert bad.status_code == 400


async def test_the_resources_task_checks_its_input(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)

    refused = await tasks._docker_container_resources(
        str(machine.id), "web", {"memory_bytes": "1; reboot"}
    )
    done = await tasks._docker_container_resources(str(machine.id), "web", {"cpus": 1.0})

    assert refused["ok"] is False
    assert done == {"ok": True}
    assert machine_shell.short[-1].endswith("$D update --cpus 1 web")
