"""The two ways into the Docker tab that are not ordinary pages: a Git
stack's webhook (`/hooks/docker/<token>`, no session — the token is the
credential) and the container shell (`?container=` on the machine
terminal's WebSocket)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.docker import DockerJobKind, DockerStack, StackSource
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.ssh.docker_cli import build_shell_command
from app.web.routes import terminal_ws as terminal_ws_module
from app.web.routes.terminal_ws import terminal_websocket
from tests.test_docker_web_support import (
    RUN_JOB_TASK,
    add_stack,
    audit_entries,
    get_row,
    jobs_of,
    make_docker_machine,
)
from tests.test_terminal import _FakeConnection, _FakeProcess, _FakeWebSocket, _make_session_token

# --- Webhook -----------------------------------------------------------------


async def test_the_right_token_deploys_the_stack(
    anonymous_client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, token = await add_stack(db_session_factory, machine_id, with_webhook=True)
    assert token is not None

    # Whatever the caller sends is ignored: it cannot choose what is deployed.
    response = await anonymous_client.post(
        f"/hooks/docker/{token}", json={"repository": {"clone_url": "https://evil.example/x.git"}}
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 202
    assert response.headers["cache-control"] == "no-store"
    assert (job.kind, job.target, job.ref_id, job.params) == (
        DockerJobKind.STACK_DEPLOY,
        "site",
        stack_id,
        {"pull": True},
    )
    assert job.started_by == "Git webhook (automatic)"
    assert celery_calls.names == [RUN_JOB_TASK]
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.webhook_deploy")
    assert entry.actor == "Git webhook (automatic)"
    assert entry.target_id == str(machine_id)
    assert token not in str(entry.details) and token not in entry.summary
    stack = await get_row(db_session_factory, DockerStack, stack_id)
    assert stack is not None and stack.webhook_last_at is not None
    assert stack.git_url == "https://git.example.test/ops/site.git"


@pytest.mark.parametrize(
    "path",
    ["/hooks/docker/wrong-token", "/hooks/docker/" + "x" * 200, "/hooks/docker/"],
    ids=["wrong", "too-long", "missing"],
)
async def test_a_wrong_or_missing_token_is_not_found(
    anonymous_client, db_session_factory, celery_calls, path
):
    machine_id = await make_docker_machine(db_session_factory)
    await add_stack(db_session_factory, machine_id, with_webhook=True)

    response = await anonymous_client.post(path)

    assert response.status_code == 404
    assert celery_calls == []
    assert await jobs_of(db_session_factory, machine_id) == []


async def test_the_hash_itself_is_not_a_token(anonymous_client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _token = await add_stack(db_session_factory, machine_id, with_webhook=True)
    stack = await get_row(db_session_factory, DockerStack, stack_id)
    assert stack is not None and stack.webhook_token_hash

    response = await anonymous_client.post(f"/hooks/docker/{stack.webhook_token_hash}")

    assert response.status_code == 404
    assert celery_calls == []


async def test_only_post_is_accepted(anonymous_client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    _stack_id, token = await add_stack(db_session_factory, machine_id, with_webhook=True)

    response = await anonymous_client.get(f"/hooks/docker/{token}")

    assert response.status_code == 405
    assert celery_calls == []


async def test_a_stack_that_left_git_no_longer_answers(
    anonymous_client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, token = await add_stack(db_session_factory, machine_id, with_webhook=True)
    async with db_session_factory() as session:
        stack = await session.get(DockerStack, stack_id)
        assert stack is not None
        stack.source = StackSource.EDITOR
        await session.commit()

    response = await anonymous_client.post(f"/hooks/docker/{token}")

    assert response.status_code == 404
    assert celery_calls == []


@pytest.mark.parametrize("change", ["unpinned", "inactive"])
async def test_a_machine_that_cannot_be_reached_safely_no_longer_answers(
    anonymous_client, db_session_factory, celery_calls, change
):
    machine_id = await make_docker_machine(db_session_factory)
    _stack_id, token = await add_stack(db_session_factory, machine_id, with_webhook=True)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        if change == "unpinned":
            machine.host_key_fingerprint = None
        else:
            machine.is_active = False
        await session.commit()

    response = await anonymous_client.post(f"/hooks/docker/{token}")

    assert response.status_code == 404
    assert celery_calls == []


async def test_calls_close_together_deploy_once(anonymous_client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    _stack_id, token = await add_stack(db_session_factory, machine_id, with_webhook=True)

    first = await anonymous_client.post(f"/hooks/docker/{token}")
    second = await anonymous_client.post(f"/hooks/docker/{token}")

    assert first.status_code == second.status_code == 202
    assert len(await jobs_of(db_session_factory, machine_id)) == 1
    assert celery_calls.names == [RUN_JOB_TASK]


async def test_a_deploy_already_waiting_is_not_queued_again(
    anonymous_client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, token = await add_stack(db_session_factory, machine_id, with_webhook=True)

    await anonymous_client.post(f"/hooks/docker/{token}")
    async with db_session_factory() as session:
        stack = await session.get(DockerStack, stack_id)
        assert stack is not None
        stack.webhook_last_at = datetime.now(UTC) - timedelta(minutes=5)
        await session.commit()
    again = await anonymous_client.post(f"/hooks/docker/{token}")

    assert again.status_code == 202
    assert len(await jobs_of(db_session_factory, machine_id)) == 1
    assert len(await audit_entries(db_session_factory, "machine.docker.stack.webhook_deploy")) == 1


async def test_debcontrols_own_project_is_never_deployed_by_webhook(
    anonymous_client, db_session_factory, celery_calls, monkeypatch
):
    async def _own_project(db, machine):
        return "site"

    monkeypatch.setattr("app.services.docker_jobs.protected_project", _own_project)
    machine_id = await make_docker_machine(db_session_factory)
    _stack_id, token = await add_stack(db_session_factory, machine_id, with_webhook=True)

    response = await anonymous_client.post(f"/hooks/docker/{token}")

    assert response.status_code == 202
    assert celery_calls == []
    assert await jobs_of(db_session_factory, machine_id) == []


# --- Container shell over the terminal WebSocket ------------------------------


@pytest.mark.parametrize("container", ["x;id", "-it", "$(reboot)", "a b", "../web"])
async def test_shell_websocket_rejects_an_invalid_container_name(
    db_session_factory, monkeypatch, container
):
    machine_id = await make_docker_machine(db_session_factory)
    token = await _make_session_token(db_session_factory, permissions={Permission.ACTION_TERMINAL})

    async def _must_not_connect(*args, **kwargs):
        raise AssertionError("no SSH session may be opened for an invalid container")

    monkeypatch.setattr(terminal_ws_module, "open_shell_session", _must_not_connect)
    ws = _FakeWebSocket(db_session_factory, token=token, query={"container": container})

    await terminal_websocket(ws, machine_id)  # type: ignore[arg-type]

    assert ws.closed == (1008, "Invalid container.")
    assert not ws.accepted


async def test_shell_websocket_still_needs_action_terminal(db_session_factory, monkeypatch):
    machine_id = await make_docker_machine(db_session_factory)
    token = await _make_session_token(
        db_session_factory, permissions={Permission.MACHINE_VIEW, Permission.ACTION_UPDATES}
    )

    async def _must_not_connect(*args, **kwargs):
        raise AssertionError("no SSH session without action.terminal")

    monkeypatch.setattr(terminal_ws_module, "open_shell_session", _must_not_connect)
    ws = _FakeWebSocket(db_session_factory, token=token, query={"container": "web"})

    await terminal_websocket(ws, machine_id)  # type: ignore[arg-type]

    assert ws.closed is not None and ws.closed[0] == 1008
    assert not ws.accepted


async def test_shell_websocket_execs_into_the_container_and_audits_it(
    db_session_factory, monkeypatch
):
    machine_id = await make_docker_machine(db_session_factory)
    token = await _make_session_token(db_session_factory, permissions={Permission.ACTION_TERMINAL})
    commands: list[str | None] = []

    async def _fake_open_shell_session(
        machine, secret, timeout_seconds, *, term_type, term_size, command=None
    ):
        commands.append(command)
        return _FakeConnection(), _FakeProcess()

    monkeypatch.setattr(terminal_ws_module, "open_shell_session", _fake_open_shell_session)
    ws = _FakeWebSocket(db_session_factory, token=token, query={"container": "web"})

    await terminal_websocket(ws, machine_id)  # type: ignore[arg-type]

    assert ws.accepted
    assert commands == [build_shell_command("web")]
    async with db_session_factory() as session:
        entries = list(
            (await session.execute(select(AuditLogEntry).order_by(AuditLogEntry.sequence)))
            .scalars()
            .all()
        )
    by_action = {entry.action: entry for entry in entries}
    assert "machine.terminal.open" not in by_action
    opened = by_action["machine.container.shell.open"]
    closed = by_action["machine.container.shell.close"]
    assert opened.details == {"container": "web"}
    assert closed.details is not None and closed.details["container"] == "web"
    assert 'container "web"' in opened.summary
