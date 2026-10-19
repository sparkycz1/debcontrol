"""REST API of the Docker tab: managed stacks and Compose projects
(`app/web/routes/api_v1_docker.py`)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select, update

from app.db.models.docker import DockerJob, DockerJobKind, DockerJobStatus, DockerStack
from app.db.models.role import Permission
from app.services import docker_jobs
from tests.test_api_v1_docker import (
    INVENTORY,
    add_job,
    audit_actions,
    base,
    docker_machine,
    headers_for,
)
from tests.test_api_v1_extended import _api_token

COMPOSE = "services:\n  web:\n    image: nginx:1.27\n"
GIT_TOKEN = "ghp_supersecrettoken123"
ENV_SECRET = "DB_PASSWORD=hunter2-env-secret"
SYNC = "app.tasks.docker_jobs.sync_git_stack"
COMPOSE_FILE = "app.tasks.docker_jobs.docker_compose_file"


async def create_stack(client: Any, machine_id: str, headers: dict[str, str], **extra: Any) -> Any:
    payload: dict[str, Any] = {"name": "shop", "compose": COMPOSE, "env": ENV_SECRET}
    payload.update(extra)
    return await client.post(f"{base(machine_id)}/stacks", json=payload, headers=headers)


async def test_create_editor_stack_and_read_it_back(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    created = await create_stack(client, machine_id, headers, name="  Shop ")
    assert created.status_code == 201, created.text
    stack = created.json()["stack"]
    assert stack["name"] == "shop"
    assert stack["source"] == "editor"
    assert stack["compose"] == COMPOSE
    assert stack["env"] == ENV_SECRET
    assert "job" not in created.json()
    assert ("machine.docker.stack.create", "success") in await audit_actions(db_session_factory)

    # The env is stored encrypted.
    async with db_session_factory() as session:
        row = (await session.execute(select(DockerStack))).scalar_one()
        assert row.env_encrypted is not None
        assert ENV_SECRET.encode() not in row.env_encrypted

    full = await client.get(f"{base(machine_id)}/stacks/{stack['id']}", headers=headers)
    assert full.status_code == 200
    assert full.json()["env"] == ENV_SECRET
    assert full.json()["jobs"] == []

    # machine.view alone: no compose file, no .env.
    viewer = await headers_for(client, login_as, {Permission.MACHINE_VIEW})
    listed = await client.get(f"{base(machine_id)}/stacks", headers=viewer)
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert "env" not in listed.json()[0]
    assert "compose" not in listed.json()[0]
    one = await client.get(f"{base(machine_id)}/stacks/{stack['id']}", headers=viewer)
    assert one.status_code == 200
    assert "env" not in one.json()
    assert ENV_SECRET not in one.text


async def test_git_stack_token_is_write_only(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    created = await create_stack(
        client,
        machine_id,
        headers,
        source="git",
        compose="",
        git_url="https://git.example.com/me/shop.git",
        git_token=GIT_TOKEN,
        auto_sync=True,
    )
    assert created.status_code == 201, created.text
    assert GIT_TOKEN not in created.text
    stack = created.json()["stack"]
    assert stack["has_git_token"] is True
    assert stack["git_branch"] == "main"
    assert stack["git_compose_path"] == "compose.yaml"
    url = f"{base(machine_id)}/stacks/{stack['id']}"

    for response in (
        await client.get(url, headers=headers),
        await client.get(f"{base(machine_id)}/stacks", headers=headers),
    ):
        assert response.status_code == 200
        assert GIT_TOKEN not in response.text

    # None keeps the token...
    kept = await client.put(
        url,
        json={"source": "git", "git_url": "https://git.example.com/me/shop.git"},
        headers=headers,
    )
    assert kept.status_code == 200, kept.text
    assert kept.json()["stack"]["has_git_token"] is True
    assert GIT_TOKEN not in kept.text
    # ... and "" removes it.
    removed = await client.put(
        url,
        json={"source": "git", "git_url": "https://git.example.com/me/shop.git", "git_token": ""},
        headers=headers,
    )
    assert removed.json()["stack"]["has_git_token"] is False

    async with db_session_factory() as session:
        audits = (
            await session.execute(
                select(DockerStack.git_token_encrypted).where(
                    DockerStack.id == uuid.UUID(stack["id"])
                )
            )
        ).scalar_one()
    assert audits is None


async def test_stack_create_validation(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    bad_compose = await create_stack(client, machine_id, headers, compose="not: [yaml")
    assert bad_compose.status_code == 422
    assert "docker.stack.error.compose" in bad_compose.json()["detail"]

    bad_name = await create_stack(client, machine_id, headers, name="has space")
    assert bad_name.status_code == 422
    assert "docker.stack.error.name" in bad_name.json()["detail"]

    bad_git = await create_stack(
        client, machine_id, headers, source="git", git_url="ssh://git@example.com/x.git"
    )
    assert bad_git.status_code == 422
    assert "docker.stack.error.git_url" in bad_git.json()["detail"]

    bad_source = await create_stack(client, machine_id, headers, source="svn")
    assert bad_source.status_code == 422
    too_long = await create_stack(client, machine_id, headers, name="a" * 65)
    assert too_long.status_code == 422

    assert (await create_stack(client, machine_id, headers)).status_code == 201
    taken = await create_stack(client, machine_id, headers)
    assert taken.status_code == 422
    assert "docker.stack.error.name_taken" in taken.json()["detail"]


async def test_stack_create_refuses_debcontrols_own_project(
    client, db_session_factory, monkeypatch
):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    async def _protected(db: Any, machine: Any) -> str:
        return "debcontrol"

    monkeypatch.setattr(docker_jobs, "protected_project", _protected)
    response = await create_stack(client, machine_id, headers, name="debcontrol")
    assert response.status_code == 422
    assert "docker.stack.error.protected" in response.json()["detail"]


async def test_stack_write_permissions(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    stack_id = (await create_stack(client, machine_id, headers)).json()["stack"]["id"]
    url = f"{base(machine_id)}/stacks/{stack_id}"

    for perms, username in (
        ({Permission.MACHINE_VIEW}, "dk-view"),
        ({Permission.MACHINE_VIEW, Permission.ACTION_UPDATES}, "dk-upd"),
        ({Permission.MACHINE_VIEW, Permission.ACTION_POWER}, "dk-pow"),
    ):
        limited = await headers_for(client, login_as, perms, username=username)
        create = await create_stack(client, machine_id, limited, name="other")
        assert create.status_code == 403, username
        assert (
            await client.put(url, json={"compose": COMPOSE}, headers=limited)
        ).status_code == 403
        deleted = await client.delete(url, headers=limited)
        assert deleted.status_code == 403
        assert (await client.post(f"{url}/webhook", headers=limited)).status_code == 403

    viewer = await headers_for(client, login_as, {Permission.MACHINE_VIEW}, username="dk-v2")
    assert (await client.post(f"{url}/deploy", headers=viewer)).status_code == 403
    assert (await client.post(f"{url}/sync", headers=viewer)).status_code == 403

    terminal = await headers_for(client, login_as, {Permission.ACTION_TERMINAL}, username="dk-term")
    # Editing is action.terminal; deploying is action.updates.
    assert (await client.post(f"{url}/deploy", headers=terminal)).status_code == 403
    saved = await client.put(url, json={"compose": COMPOSE}, headers=terminal)
    assert saved.status_code == 200, saved.text


async def test_stack_save_with_deploy_needs_updates(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    stack_id = (await create_stack(client, machine_id, headers)).json()["stack"]["id"]
    terminal = await headers_for(client, login_as, {Permission.ACTION_TERMINAL}, username="dk-term")
    response = await client.put(
        f"{base(machine_id)}/stacks/{stack_id}",
        json={"compose": COMPOSE, "deploy": True},
        headers=terminal,
    )
    assert response.status_code == 403


async def test_stack_create_with_deploy_queues_a_job(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    response = await create_stack(client, machine_id, headers, deploy=True)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["job"]["kind"] == "stack_deploy"
    assert body["job"]["params"] == {"pull": True}
    assert body["job"]["target"] == "shop"


async def test_stack_save_keeps_name_and_env_when_omitted(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    stack_id = (await create_stack(client, machine_id, headers)).json()["stack"]["id"]
    url = f"{base(machine_id)}/stacks/{stack_id}"

    new_compose = COMPOSE + "  db:\n    image: postgres:17\n"
    saved = await client.put(url, json={"name": "renamed", "compose": new_compose}, headers=headers)
    assert saved.status_code == 200, saved.text
    stack = saved.json()["stack"]
    assert stack["name"] == "shop"
    assert stack["compose"] == new_compose
    assert stack["env"] == ENV_SECRET
    assert "job" not in saved.json()

    invalid = await client.put(url, json={"compose": ""}, headers=headers)
    assert invalid.status_code == 422

    cleared = await client.put(url, json={"compose": COMPOSE, "env": ""}, headers=headers)
    assert cleared.json()["stack"]["env"] == ""


async def test_stack_directory_is_chosen_on_create_only(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    created = await create_stack(client, machine_id, headers, directory="~/apps/shop")
    assert created.status_code == 201, created.text
    stack = created.json()["stack"]
    assert stack["directory"] == "~/apps/shop"
    url = f"{base(machine_id)}/stacks/{stack['id']}"

    same = await client.put(url, json={"compose": COMPOSE, "directory": "~/apps/shop"},
                            headers=headers)
    assert same.status_code == 200
    moved = await client.put(url, json={"compose": COMPOSE, "directory": "/opt/shop"},
                             headers=headers)
    assert moved.status_code == 422
    assert moved.json()["detail"] == ["docker.stack.error.directory_fixed"]

    invalid = await create_stack(client, machine_id, headers, name="other", directory="/usr/x")
    assert invalid.status_code == 422
    assert invalid.json()["detail"] == ["docker.stack.error.directory"]
    taken = await create_stack(client, machine_id, headers, name="other", directory="~/apps/shop")
    assert taken.json()["detail"] == ["docker.stack.error.directory_taken"]
    default = await create_stack(client, machine_id, headers, name="plain")
    assert default.json()["stack"]["directory"] is None


async def test_stack_deploy(client, db_session_factory, monkeypatch):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    stack_id = (await create_stack(client, machine_id, headers)).json()["stack"]["id"]
    url = f"{base(machine_id)}/stacks/{stack_id}/deploy"

    queued = await client.post(url, json={"pull": False}, headers=headers)
    assert queued.status_code == 202, queued.text
    assert queued.json()["job"]["params"] == {"pull": False}
    assert ("machine.docker.stack.deploy", "success") in await audit_actions(db_session_factory)

    busy = await client.post(url, headers=headers)
    assert busy.status_code == 409

    job = await client.get(f"{base(machine_id)}/stacks/{stack_id}", headers=headers)
    assert len(job.json()["jobs"]) == 1

    async def _protected(db: Any, machine: Any) -> str:
        return "shop"

    monkeypatch.setattr(docker_jobs, "protected_project", _protected)
    assert (await client.post(url, headers=headers)).status_code == 409


async def test_stacks_of_other_machines_are_404(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    other_id = await docker_machine(client, db_session_factory, headers, name="dock-other")
    foreign = (await create_stack(client, other_id, headers)).json()["stack"]["id"]
    url = f"{base(machine_id)}/stacks/{foreign}"

    assert (await client.get(url, headers=headers)).status_code == 404
    assert (await client.put(url, json={"compose": COMPOSE}, headers=headers)).status_code == 404
    deleted = await client.delete(url, headers=headers)
    assert deleted.status_code == 404
    assert (await client.post(f"{url}/deploy", headers=headers)).status_code == 404
    assert (await client.post(f"{url}/sync", headers=headers)).status_code == 404
    assert (await client.post(f"{url}/webhook", headers=headers)).status_code == 404
    assert (await client.get(f"{base(machine_id)}/stacks", headers=headers)).json() == []
    random = await client.get(f"{base(machine_id)}/stacks/{uuid.uuid4()}", headers=headers)
    assert random.status_code == 404


async def test_git_sync_and_webhook(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    editor_id = (await create_stack(client, machine_id, headers)).json()["stack"]["id"]
    git = await create_stack(
        client,
        machine_id,
        headers,
        name="gitshop",
        source="git",
        git_url="https://git.example.com/me/shop.git",
    )
    git_id = git.json()["stack"]["id"]

    for what in ("sync", "webhook"):
        not_git = await client.post(
            f"{base(machine_id)}/stacks/{editor_id}/{what}", headers=headers
        )
        assert not_git.status_code == 400, what

    celery_calls.result_for[SYNC] = {"ok": True, "deployed": True, "commit": "abc123"}
    synced = await client.post(f"{base(machine_id)}/stacks/{git_id}/sync", headers=headers)
    assert synced.status_code == 200, synced.text
    assert synced.json()["deployed"] is True
    assert synced.json()["commit"] == "abc123"

    celery_calls.result_for[SYNC] = {"ok": False, "error": "git said no"}
    failed = await client.post(f"{base(machine_id)}/stacks/{git_id}/sync", headers=headers)
    assert failed.status_code == 502
    assert ("machine.docker.stack.sync", "failure") in await audit_actions(db_session_factory)

    hook = await client.post(f"{base(machine_id)}/stacks/{git_id}/webhook", headers=headers)
    assert hook.status_code == 200, hook.text
    webhook_url = hook.json()["webhook_url"]
    assert webhook_url.startswith("http://testserver/hooks/docker/")
    token = webhook_url.rsplit("/", 1)[1]
    detail = await client.get(f"{base(machine_id)}/stacks/{git_id}", headers=headers)
    assert detail.json()["has_webhook"] is True
    assert token not in detail.text

    gone = await client.post(
        f"{base(machine_id)}/stacks/{git_id}/webhook", json={"remove": True}, headers=headers
    )
    assert gone.json() == {"webhook_url": None}
    detail = await client.get(f"{base(machine_id)}/stacks/{git_id}", headers=headers)
    assert detail.json()["has_webhook"] is False


async def test_delete_never_deployed_stack(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    stack_id = (await create_stack(client, machine_id, headers)).json()["stack"]["id"]
    response = await client.delete(f"{base(machine_id)}/stacks/{stack_id}", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json() == {"deleted": True, "job": None}
    assert (await client.get(f"{base(machine_id)}/stacks", headers=headers)).json() == []


async def test_delete_deployed_stack_with_volumes_needs_confirm(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    stack_id = (await create_stack(client, machine_id, headers)).json()["stack"]["id"]
    async with db_session_factory() as session:
        stack = await session.get(DockerStack, uuid.UUID(stack_id))
        assert stack is not None
        stack.last_status = "running"
        await session.commit()
    url = f"{base(machine_id)}/stacks/{stack_id}"

    unconfirmed = await client.delete(f"{url}?remove_volumes=true&confirm=wrong", headers=headers)
    assert unconfirmed.status_code == 400
    assert ("machine.docker.stack.delete", "denied") in await audit_actions(db_session_factory)

    confirmed = await client.delete(f"{url}?remove_volumes=true&confirm=shop", headers=headers)
    assert confirmed.status_code == 200, confirmed.text
    body = confirmed.json()
    assert body["deleted"] is False
    assert body["job"]["params"] == {"action": "remove", "volumes": True}

    # Without volumes no confirmation is needed (but a removal is queued already).
    busy = await client.delete(url, headers=headers)
    assert busy.status_code == 409


async def finish_jobs(db_session_factory: Any) -> None:
    async with db_session_factory() as session:
        await session.execute(update(DockerJob).values(status=DockerJobStatus.SUCCEEDED))
        await session.commit()


# --- Compose projects ---------------------------------------------------------------


PROJECT_INVENTORY = {
    "ok": True,
    "inventory": {
        "compose": [
            {"name": "shop", "status": "running(2)", "config_files": ["/srv/shop/compose.yaml"]}
        ],
        "containers": [
            {
                "name": "web",
                "compose_project": "shop",
                "compose_working_dir": "/srv/shop",
            },
            {
                "name": "loose",
                "compose_project": "adhoc",
                "compose_working_dir": "/srv/adhoc",
                "compose_config_files": [],
            },
            {"name": "plain"},
        ],
    },
}


async def test_projects_list(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    stack_id = (await create_stack(client, machine_id, headers)).json()["stack"]["id"]
    celery_calls.result_for[INVENTORY] = PROJECT_INVENTORY

    response = await client.get(f"{base(machine_id)}/projects", headers=headers)
    assert response.status_code == 200, response.text
    projects = {p["name"]: p for p in response.json()}
    assert set(projects) == {"adhoc", "shop"}
    assert projects["shop"]["stack_id"] == stack_id
    assert projects["shop"]["working_dir"] == "/srv/shop"
    assert projects["shop"]["containers"] == ["web"]
    assert projects["adhoc"]["stack_id"] is None


async def test_project_actions_and_permissions(client, login_as, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    celery_calls.result_for[INVENTORY] = PROJECT_INVENTORY
    url = f"{base(machine_id)}/projects"

    stopped = await client.post(f"{url}/shop/stop", headers=headers)
    assert stopped.status_code == 202, stopped.text
    assert stopped.json()["job"]["params"] == {"action": "stop"}
    assert ("machine.docker.stack.action", "success") in await audit_actions(db_session_factory)
    assert (await client.post(f"{url}/shop/stop", headers=headers)).status_code == 409
    await finish_jobs(db_session_factory)

    up = await client.post(f"{url}/shop/up", headers=headers)
    assert up.status_code == 202, up.text
    assert up.json()["job"]["params"] == {
        "action": "up",
        "working_dir": "/srv/shop",
        "files": ["/srv/shop/compose.yaml"],
    }

    unknown_files = await client.post(f"{url}/adhoc/update", headers=headers)
    assert unknown_files.status_code == 400
    assert (await client.post(f"{url}/shop/explode", headers=headers)).status_code == 400
    assert (await client.post(f"{url}/Bad Name/stop", headers=headers)).status_code == 400

    viewer = await headers_for(client, login_as, {Permission.MACHINE_VIEW})
    assert (await client.post(f"{url}/shop/restart", headers=viewer)).status_code == 403
    assert (await client.post(f"{url}/shop/up", headers=viewer)).status_code == 403

    await finish_jobs(db_session_factory)
    power = await headers_for(client, login_as, {Permission.ACTION_POWER}, username="dk-pow")
    assert (await client.post(f"{url}/shop/restart", headers=power)).status_code == 202
    await finish_jobs(db_session_factory)
    assert (await client.post(f"{url}/shop/update", headers=power)).status_code == 403
    await finish_jobs(db_session_factory)

    updates = await headers_for(client, login_as, {Permission.ACTION_UPDATES}, username="dk-up")
    assert (await client.post(f"{url}/shop/down", headers=updates)).status_code == 403
    assert (await client.post(f"{url}/shop/update", headers=updates)).status_code == 202


async def test_project_action_on_managed_stack_deploys(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    await create_stack(client, machine_id, headers)
    response = await client.post(f"{base(machine_id)}/projects/shop/update", headers=headers)
    assert response.status_code == 202, response.text
    assert response.json()["job"]["kind"] == DockerJobKind.STACK_DEPLOY


async def test_project_action_protected(client, db_session_factory, monkeypatch):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    async def _protected(db: Any, machine: Any) -> str:
        return "debcontrol"

    monkeypatch.setattr(docker_jobs, "protected_project", _protected)
    down = await client.post(f"{base(machine_id)}/projects/debcontrol/down", headers=headers)
    assert down.status_code == 409
    assert ("machine.docker.stack.action", "denied") in await audit_actions(db_session_factory)
    # Starting is harmless and stays possible.
    start = await client.post(f"{base(machine_id)}/projects/debcontrol/start", headers=headers)
    assert start.status_code == 202


async def test_project_action_needs_host_key(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers, ready=False)
    response = await client.post(f"{base(machine_id)}/projects/shop/stop", headers=headers)
    assert response.status_code == 400


async def test_project_compose_files(client, login_as, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    celery_calls.result_for[INVENTORY] = PROJECT_INVENTORY
    celery_calls.result_for[COMPOSE_FILE] = {"ok": True, "content": COMPOSE}

    response = await client.get(f"{base(machine_id)}/projects/shop/compose", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["working_dir"] == "/srv/shop"
    assert body["files"] == [{"path": "/srv/shop/compose.yaml", "content": COMPOSE, "error": None}]

    missing = await client.get(f"{base(machine_id)}/projects/nope/compose", headers=headers)
    assert missing.status_code == 404

    viewer = await headers_for(
        client, login_as, {Permission.MACHINE_VIEW, Permission.ACTION_UPDATES}
    )
    denied = await client.get(f"{base(machine_id)}/projects/shop/compose", headers=viewer)
    assert denied.status_code == 403


async def test_stack_jobs_listed_on_stack(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    stack_id = (await create_stack(client, machine_id, headers)).json()["stack"]["id"]
    await add_job(
        db_session_factory,
        machine_id,
        kind=DockerJobKind.STACK_DEPLOY,
        target="shop",
        status=DockerJobStatus.FAILED,
        ref_id=uuid.UUID(stack_id),
    )
    detail = await client.get(f"{base(machine_id)}/stacks/{stack_id}", headers=headers)
    assert [j["status"] for j in detail.json()["jobs"]] == ["failed"]


async def test_create_with_deploy_without_updates_creates_nothing(
    client, login_as, db_session_factory
):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    terminal = await headers_for(client, login_as, {Permission.ACTION_TERMINAL}, username="dk-term")
    response = await create_stack(client, machine_id, terminal, deploy=True)
    assert response.status_code == 403
    assert (await client.get(f"{base(machine_id)}/stacks", headers=headers)).json() == []


WRITE_COMPOSE = "app.tasks.docker_jobs.docker_write_compose_file"


async def test_project_compose_file_save(client, login_as, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    celery_calls.result_for[INVENTORY] = PROJECT_INVENTORY
    celery_calls.result_for[WRITE_COMPOSE] = {"ok": True}
    url = f"{base(machine_id)}/projects/shop/compose"
    body = {"path": "/srv/shop/compose.yaml", "content": COMPOSE}

    saved = await client.put(url, json=body, headers=headers)
    assert saved.status_code == 200, saved.text
    assert saved.json() == {"saved": True, "path": "/srv/shop/compose.yaml"}
    [write] = [args for name, args, _kw in celery_calls if name == WRITE_COMPOSE]
    assert write == (
        machine_id, "shop", "/srv/shop/compose.yaml", COMPOSE, "/srv/shop",
        ["/srv/shop/compose.yaml"],
    )
    assert ("machine.docker.project.compose_edit", "success") in await audit_actions(
        db_session_factory
    )

    applied = await client.put(url, json={**body, "up": True}, headers=headers)
    assert applied.status_code == 200
    assert applied.json()["job"]["kind"] == DockerJobKind.STACK_ACTION

    celery_calls.result_for[WRITE_COMPOSE] = {"ok": False, "step": "config", "error": "bad"}
    rejected = await client.put(url, json=body, headers=headers)
    assert rejected.status_code == 422
    assert ("machine.docker.project.compose_edit", "failure") in await audit_actions(
        db_session_factory
    )

    other = await client.put(url, json={**body, "path": "/etc/passwd"}, headers=headers)
    assert other.status_code == 400
    invalid = await client.put(f"{base(machine_id)}/projects/Bad;x/compose", json=body,
                               headers=headers)
    assert invalid.status_code == 404

    # A stack debcontrol deploys is changed through /stacks.
    await create_stack(client, machine_id, headers)
    managed = await client.put(url, json=body, headers=headers)
    assert managed.status_code == 400

    viewer = await headers_for(
        client, login_as, {Permission.MACHINE_VIEW, Permission.ACTION_TERMINAL}
    )
    no_updates = await client.put(url, json={**body, "up": True}, headers=viewer)
    assert no_updates.status_code == 403
