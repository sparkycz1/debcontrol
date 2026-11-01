"""Moving or cloning a stack to another machine with its data: what is
copied (and what never is), the checks before anything happens, the job
end to end with both machines' SSH side faked, and the web and API
entry points with their permissions and audit."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.docker import (
    DockerJob,
    DockerJobKind,
    DockerJobStatus,
    DockerStack,
    StackSource,
)
from app.db.models.machine import AuthMethod, Machine
from app.db.models.role import Permission
from app.services import docker_jobs as docker_jobs_service
from app.services import self_host
from app.ssh import docker_transfer
from app.ssh.docker_cli import DockerCommandError
from app.tasks import docker_jobs as tasks
from tests.conftest import RecordedCeleryCalls
from tests.test_docker_tasks_jobs import (
    FakeMachine,
    _add,
    _get,
    _job,
    _machine,
    install_fake_machine,
)
from tests.test_docker_web_support import audit_entries
from tests.test_update_history import _api_token

RUN_JOB = "app.tasks.docker_jobs.run_docker_job"


def _volume(name: str, project: str = "shop", **extra: Any) -> str:
    body = {
        "Name": name,
        "Driver": "local",
        "Options": None,
        "Labels": {
            "com.docker.compose.project": project,
            "com.docker.compose.volume": name.split("_", 1)[-1],
        },
        **extra,
    }
    return "@@VOL " + json.dumps(body)


def _container(running: bool, mounts: list[dict[str, Any]], wd: str = "/srv/stacks/shop") -> str:
    return f"@@CT {'true' if running else 'false'}\t{wd}\t{json.dumps(mounts)}"


INVENTORY = "\n".join(
    [
        _volume("shop_db"),
        _volume("shop_nfs", Driver="nfs"),
        _volume("shop_bind", Options={"type": "none", "o": "bind"}),
        _volume("other_x", project="other"),
        '@@VOL {"Name": "-evil", "Driver": "local", "Labels": '
        '{"com.docker.compose.project": "shop"}}',
        _container(
            True,
            [
                {"Type": "volume", "Name": "shop_db", "Source": "/var/lib/docker/x"},
                {"Type": "bind", "Source": "/srv/stacks/shop/data"},
                {"Type": "bind", "Source": "/srv/stacks/shop/data/sub"},
                {"Type": "bind", "Source": "/srv/stacks/shop/nginx.conf"},
                {"Type": "bind", "Source": "/srv/media"},
                {"Type": "bind", "Source": "/srv/stacks/shop/repo/config"},
                {"Type": "bind", "Source": "/srv/stacks/shop/.env"},
            ],
        ),
        _container(False, []),
        "@@END",
    ]
)


def test_inventory_takes_only_the_projects_plain_local_volumes() -> None:
    inventory = docker_transfer.parse_inventory(INVENTORY, "shop")

    assert [v["name"] for v in inventory.volumes] == ["shop_db"]
    assert inventory.volumes[0]["labels"]["com.docker.compose.project"] == "shop"
    assert inventory.skipped_volumes == [
        {"name": "shop_nfs", "reason": "driver"},
        {"name": "shop_bind", "reason": "options"},
    ]
    assert inventory.running == 1
    assert inventory.working_dir == "/srv/stacks/shop"


def test_bind_paths_inside_the_stack_directory_are_copied_the_rest_listed() -> None:
    inventory = docker_transfer.parse_inventory(INVENTORY, "shop")

    paths, outside = docker_transfer.bind_paths(inventory, "/srv/stacks/shop", git=False)
    git_paths, git_outside = docker_transfer.bind_paths(inventory, "/srv/stacks/shop", git=True)

    # data/sub goes with data; the stack's own .env is written by the deploy.
    assert paths == ["data", "nginx.conf", "repo/config"]
    assert outside == ["/srv/media", "/srv/stacks/shop/.env"]
    # A Git stack's repo/ comes from the repository.
    assert git_paths == ["data", "nginx.conf"]
    assert git_outside == ["/srv/media", "/srv/stacks/shop/.env"]


def test_without_a_known_stack_directory_nothing_is_taken_from_the_host() -> None:
    inventory = docker_transfer.parse_inventory(INVENTORY, "shop")
    paths, outside = docker_transfer.bind_paths(inventory, "", git=False)
    assert paths == []
    assert "/srv/stacks/shop/data" in outside


def test_commands_quote_every_name_and_refuse_odd_ones() -> None:
    assert docker_transfer.source_volume_command("shop_db").endswith(
        "-v shop_db:/from:ro busybox:latest tar -C /from -cf - ."
    )
    assert "--log-driver none" in docker_transfer.target_volume_command("shop_db")
    assert "-i -v shop_db:/to" in docker_transfer.target_volume_command("shop_db")
    command = docker_transfer.source_paths_command("/srv/my stacks/shop", ["data", "a b"])
    assert "'/srv/my stacks/shop:/from:ro'" in command
    assert command.endswith("tar -C /from -cf - ./data './a b'")
    create = docker_transfer.build_volume_create(
        "shop_db", {"com.docker.compose.project": "shop", "bad key!": "x"}
    )
    assert create == (
        "$D volume create --label com.docker.compose.project=shop shop_db >/dev/null"
    )
    with pytest.raises(DockerCommandError):
        docker_transfer.source_volume_command("-v")
    with pytest.raises(DockerCommandError):
        docker_transfer.source_paths_command("/srv/shop", ["../etc"])
    with pytest.raises(DockerCommandError):
        docker_transfer.source_paths_command("relative", ["data"])
    with pytest.raises(DockerCommandError):
        docker_transfer.target_prepare_script("shop", "", ["-x"])


def test_target_state_is_read_from_marked_lines() -> None:
    state = docker_transfer.parse_target_state(
        "@@EXISTS shop_db\n@@DIR_NOT_EMPTY\n@@DIR /home/u/.local/share/debcontrol/stacks/shop\n"
    )
    assert state.existing_volumes == ["shop_db"]
    assert state.dir_not_empty is True
    assert state.directory == "/home/u/.local/share/debcontrol/stacks/shop"


# --- The job -----------------------------------------------------------------------


class _Streams:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []
        self.fail = False

    async def __call__(
        self,
        source: Any,
        target: Any,
        _timeout: int,
        source_command: str,
        target_command: str,
        *,
        progress: Any,
        stop_requested: Any,
    ) -> int:
        self.calls.append(
            (source.machine.name, target.machine.name, source_command, target_command)
        )
        if self.fail:
            raise DockerCommandError("tar on the target machine failed: disk full")
        await progress(2048)
        return 2048


@pytest.fixture
def machine_shell(monkeypatch: pytest.MonkeyPatch, db_session_factory: Any) -> FakeMachine:
    return install_fake_machine(monkeypatch, db_session_factory)


@pytest.fixture
def streams(monkeypatch: pytest.MonkeyPatch, machine_shell: FakeMachine) -> _Streams:
    fake = _Streams()
    monkeypatch.setattr(docker_transfer, "stream", fake)
    return fake


async def _transfer_setup(
    db_session_factory: Any, *, mode: str = "move", data: bool = True
) -> tuple[Machine, Machine, DockerStack, DockerStack, DockerJob]:
    source = _machine(name="old")
    target = _machine(name="new", ip_address="10.0.0.8", docker_containers=[])
    source_stack = DockerStack(
        machine_id=source.id, name="shop", source=StackSource.EDITOR, compose_content="x"
    )
    target_stack = DockerStack(
        machine_id=target.id, name="shop", source=StackSource.EDITOR, compose_content="x"
    )
    await _add(db_session_factory, source, target)
    await _add(db_session_factory, source_stack, target_stack)
    job = _job(
        target,
        DockerJobKind.STACK_TRANSFER,
        "shop",
        ref_id=target_stack.id,
        params={
            "source_machine_id": str(source.id),
            "source_stack_id": str(source_stack.id),
            "mode": mode,
            "data": data,
        },
    )
    await _add(db_session_factory, job)
    return source, target, source_stack, target_stack, job


def _answer_inventory(machine_shell: FakeMachine) -> None:
    machine_shell.answer("volume ls -q --filter", INVENTORY)
    machine_shell.answer("pwd -P || true", "/srv/stacks/shop\n")
    machine_shell.answer("@@DIR $(pwd -P)", "@@DIR /home/u/stacks/shop\n")


async def test_a_move_copies_volumes_and_files_then_deploys_and_leaves_the_source_stopped(
    db_session_factory: Any,
    machine_shell: FakeMachine,
    streams: _Streams,
    celery_calls: RecordedCeleryCalls,
) -> None:
    _answer_inventory(machine_shell)
    _source, _target, _src, target_stack, job = await _transfer_setup(db_session_factory)

    await tasks._run_docker_job(str(job.id))

    done = await _get(db_session_factory, DockerJob, job.id)
    assert done.status == DockerJobStatus.SUCCEEDED, done.error
    assert done.result["volumes"] == ["shop_db"]
    assert done.result["paths"] == ["data", "nginx.conf", "repo/config"]
    assert done.result["not_copied"] == ["/srv/media", "/srv/stacks/shop/.env"]
    assert done.result["bytes"] == 4096
    assert [(c[0], c[1]) for c in streams.calls] == [("old", "new"), ("old", "new")]
    assert "shop_db:/from:ro" in streams.calls[0][2]
    assert "-v /home/u/stacks/shop:/to busybox" in streams.calls[1][3]
    stops = [s for s in machine_shell.short if "compose -p shop stop" in s]
    starts = [s for s in machine_shell.short if "compose -p shop start" in s]
    assert len(stops) == 1
    assert starts == []
    # Down, not just stopped: `restart: always` would bring it back on a reboot.
    assert sum("compose -p shop down" in s for s in machine_shell.short) == 1
    assert any("volume create" in s and "shop_db" in s for s in machine_shell.short)
    assert "Not copied (outside the stack's directory): /srv/media" in done.output
    # The deploy on the target is its own job.
    async with db_session_factory() as db:
        deploys = (
            (await db.execute(select(DockerJob).where(DockerJob.kind == "stack_deploy")))
            .scalars()
            .all()
        )
    assert [d.ref_id for d in deploys] == [target_stack.id]
    assert done.result["deploy_job_id"] == str(deploys[0].id)


async def test_a_clone_starts_the_source_again(
    db_session_factory: Any, machine_shell: FakeMachine, streams: _Streams
) -> None:
    _answer_inventory(machine_shell)
    *_rest, job = await _transfer_setup(db_session_factory, mode="copy")

    await tasks._run_docker_job(str(job.id))

    done = await _get(db_session_factory, DockerJob, job.id)
    assert done.status == DockerJobStatus.SUCCEEDED
    assert sum("compose -p shop start" in s for s in machine_shell.short) == 1
    assert not any("compose -p shop down" in s for s in machine_shell.short)


async def test_a_failed_copy_starts_the_source_again_and_deploys_nothing(
    db_session_factory: Any, machine_shell: FakeMachine, streams: _Streams
) -> None:
    _answer_inventory(machine_shell)
    streams.fail = True
    *_rest, job = await _transfer_setup(db_session_factory, mode="move")

    await tasks._run_docker_job(str(job.id))

    done = await _get(db_session_factory, DockerJob, job.id)
    assert done.status == DockerJobStatus.FAILED
    assert "disk full" in done.error
    assert sum("compose -p shop start" in s for s in machine_shell.short) == 1
    async with db_session_factory() as db:
        deploys = (
            await db.execute(select(DockerJob).where(DockerJob.kind == "stack_deploy"))
        ).scalars().all()
    assert deploys == []
    assert machine_shell.notified[-1][1]["stack"] == "shop"


async def test_existing_volumes_on_the_target_stop_it_before_anything_changes(
    db_session_factory: Any, machine_shell: FakeMachine, streams: _Streams
) -> None:
    _answer_inventory(machine_shell)
    machine_shell.answers.insert(0, ("@@DIR $(pwd -P)", _out("@@EXISTS shop_db\n@@DIR /x\n")))
    *_rest, job = await _transfer_setup(db_session_factory)

    await tasks._run_docker_job(str(job.id))

    done = await _get(db_session_factory, DockerJob, job.id)
    assert done.status == DockerJobStatus.FAILED
    assert "shop_db" in done.error
    assert not any("compose -p shop stop" in s for s in machine_shell.short)
    assert streams.calls == []


async def test_without_data_only_the_stack_is_set_up(
    db_session_factory: Any, machine_shell: FakeMachine, streams: _Streams
) -> None:
    _answer_inventory(machine_shell)
    *_rest, job = await _transfer_setup(db_session_factory, mode="copy", data=False)

    await tasks._run_docker_job(str(job.id))

    done = await _get(db_session_factory, DockerJob, job.id)
    assert done.status == DockerJobStatus.SUCCEEDED
    assert streams.calls == []
    assert not any("compose -p shop stop" in s for s in machine_shell.short)


async def test_an_interrupted_transfer_is_never_repeated_on_its_own(
    db_session_factory: Any, machine_shell: FakeMachine, streams: _Streams
) -> None:
    *_rest, job = await _transfer_setup(db_session_factory)
    async with db_session_factory() as db:
        row = await db.get(DockerJob, job.id)
        row.status = DockerJobStatus.RUNNING
        row.result = {"phase": "copy"}
        await db.commit()
        await tasks._execute(db, row)

    done = await _get(db_session_factory, DockerJob, job.id)
    assert done.status == DockerJobStatus.FAILED
    assert done.error.startswith("Interrupted when debcontrol restarted")
    assert streams.calls == []


def _out(text: str) -> Any:
    from app.ssh.docker_cli import CommandOutput

    return CommandOutput(0, text)


# --- Starting it: web and API ---------------------------------------------------------


async def _machines_with_stack(db_session_factory: Any) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    def machine(name: str, ip: str) -> Machine:
        return Machine(
            name=name,
            ip_address=ip,
            port=22,
            username="root",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:x",
            docker_status="ok",
            docker_containers=[],
        )

    source = machine("old", "10.30.0.1")
    target = machine("new", "10.30.0.2")
    await _add(db_session_factory, source, target)
    stack = DockerStack(
        machine_id=source.id,
        name="shop",
        source=StackSource.EDITOR,
        compose_content="services: {}\n",
        keep_history=True,
        webhook_token_hash="a" * 64,
    )
    await _add(db_session_factory, stack)
    return source.id, target.id, stack.id


@pytest.fixture
def no_own_host(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_find(_db: Any) -> self_host.SelfHost:
        return self_host.SelfHost(hosts=frozenset())

    monkeypatch.setattr(self_host, "find", fake_find)


async def _csrf(client: Any, url: str) -> str:
    await client.get(url)
    return str(client.cookies.get("csrftoken"))


async def test_the_stack_page_offers_the_move_and_starts_it(
    client: Any,
    db_session_factory: Any,
    celery_calls: RecordedCeleryCalls,
    no_own_host: None,
) -> None:
    source_id, target_id, stack_id = await _machines_with_stack(db_session_factory)
    page_url = f"/machines/{source_id}/docker/stacks/{stack_id}"
    page = await client.get(page_url)
    assert page.status_code == 200
    assert f'value="{target_id}"' in page.text

    response = await client.post(
        f"{page_url}/transfer",
        data={
            "csrf_token": str(client.cookies.get("csrftoken")),
            "target_machine_id": str(target_id),
            "mode": "move",
            "data": "1",
        },
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(f"/machines/{target_id}/docker/jobs/")
    async with db_session_factory() as db:
        copy = (
            await db.execute(select(DockerStack).where(DockerStack.machine_id == target_id))
        ).scalar_one()
        job = (await db.execute(select(DockerJob))).scalar_one()
    assert copy.compose_content == "services: {}\n"
    assert copy.keep_history is True
    # A webhook is a secret of its own: never copied.
    assert copy.webhook_token_hash is None
    assert job.kind == DockerJobKind.STACK_TRANSFER
    assert job.machine_id == target_id
    assert job.params == {
        "source_machine_id": str(source_id),
        "source_stack_id": str(stack_id),
        "mode": "move",
        "data": True,
    }
    assert [c[1] for c in celery_calls if c[0] == RUN_JOB] == [(str(job.id),)]
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.transfer")
    assert (entry.details or {})["target"] == "new"


async def test_the_move_is_refused_for_a_name_the_target_already_has(
    client: Any, db_session_factory: Any, no_own_host: None
) -> None:
    source_id, target_id, stack_id = await _machines_with_stack(db_session_factory)
    await _add(
        db_session_factory,
        DockerStack(machine_id=target_id, name="shop", source=StackSource.EDITOR),
    )
    page_url = f"/machines/{source_id}/docker/stacks/{stack_id}"
    token = await _csrf(client, page_url)

    response = await client.post(
        f"{page_url}/transfer",
        data={"csrf_token": token, "target_machine_id": str(target_id), "mode": "copy"},
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(page_url)
    async with db_session_factory() as db:
        assert (await db.execute(select(DockerJob))).scalars().all() == []


async def test_the_move_needs_terminal_and_updates_and_a_visible_target(
    client: Any, login_as: Any, db_session_factory: Any, no_own_host: None
) -> None:
    source_id, target_id, stack_id = await _machines_with_stack(db_session_factory)
    url = f"/machines/{source_id}/docker/stacks/{stack_id}/transfer"
    await login_as(
        client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_TERMINAL}
    )
    token = await _csrf(client, f"/machines/{source_id}/docker/stacks/{stack_id}")

    response = await client.post(
        url, data={"csrf_token": token, "target_machine_id": str(target_id), "mode": "copy"}
    )

    assert response.status_code == 403


async def test_the_move_through_the_api(
    client: Any, db_session_factory: Any, no_own_host: None
) -> None:
    source_id, target_id, stack_id = await _machines_with_stack(db_session_factory)
    headers = await _api_token(client)
    url = f"/api/v1/machines/{source_id}/docker/stacks/{stack_id}/transfer"

    bad_mode = await client.post(
        url, headers=headers, json={"target_machine_id": str(target_id), "mode": "teleport"}
    )
    unknown = await client.post(
        url, headers=headers, json={"target_machine_id": str(uuid.uuid4())}
    )
    started = await client.post(
        url, headers=headers, json={"target_machine_id": str(target_id), "mode": "copy"}
    )
    again = await client.post(
        url, headers=headers, json={"target_machine_id": str(target_id), "mode": "copy"}
    )

    assert bad_mode.status_code == 422
    assert unknown.status_code == 404
    assert unknown.json()["detail"] == "docker.transfer.error.target"
    assert started.status_code == 202
    assert started.json()["job"]["kind"] == "stack_transfer"
    assert started.json()["machine_id"] == str(target_id)
    assert again.status_code == 409


async def test_debcontrol_s_own_stack_is_never_moved(
    client: Any, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_id, target_id, stack_id = await _machines_with_stack(db_session_factory)

    async def fake_protected(_db: Any, machine: Machine) -> str | None:
        return "shop" if machine.id == source_id else None

    monkeypatch.setattr(docker_jobs_service, "protected_project", fake_protected)
    headers = await _api_token(client)

    response = await client.post(
        f"/api/v1/machines/{source_id}/docker/stacks/{stack_id}/transfer",
        headers=headers,
        json={"target_machine_id": str(target_id)},
    )

    assert response.status_code == 409
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.transfer")
    assert entry.outcome == "denied"
