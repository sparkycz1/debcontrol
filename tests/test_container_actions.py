"""Start/stop/restart a Docker container: command building/parsing
(`app.ssh.containers`), the web route and its permission gate."""

from __future__ import annotations

import pytest

from app.db.models.role import Permission
from app.ssh.containers import (
    ContainerActionError,
    build_container_action_command,
    parse_container_action_output,
)
from tests.test_docker_logs import _with_containers
from tests.test_monitoring_web import _add_monitoring_sample
from tests.test_onboarding import _make_machine


def test_command_quotes_and_probes_access():
    command = build_container_action_command("restart", "immich_server")

    assert "$D restart immich_server 2>&1;" in command
    assert "sudo -n -l" in command
    assert 'echo "@@EXIT $?"' in command


@pytest.mark.parametrize(
    ("action", "name"), [("rm", "web"), ("kill", "web"), ("stop", "x;id"), ("start", "-f")]
)
def test_command_rejects_unknown_action_or_bad_name(action, name):
    with pytest.raises(ContainerActionError):
        build_container_action_command(action, name)


def test_parse_success():
    assert parse_container_action_output("web\n@@EXIT 0\n") == "web"


def test_parse_failure_surfaces_dockers_message():
    with pytest.raises(ContainerActionError, match="No such container"):
        parse_container_action_output(
            "Error response from daemon: No such container: web\n@@EXIT 1\n"
        )


def test_parse_no_access():
    with pytest.raises(ContainerActionError, match="can't reach the Docker daemon"):
        parse_container_action_output("@@NOACCESS\n")


async def test_monitoring_table_shows_actions_per_state(client, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    await _add_monitoring_sample(db_session_factory, machine_id)
    await _with_containers(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert f"/machines/{machine_id}/containers/immich_server/restart" in response.text
    assert f"/machines/{machine_id}/containers/immich_server/stop" in response.text
    assert f"/machines/{machine_id}/containers/old/start" in response.text
    assert f"/machines/{machine_id}/containers/old/stop" not in response.text


async def test_action_dispatches_the_task_and_redirects(client, db_session_factory, celery_calls):
    machine_id = await _make_machine(db_session_factory)
    await client.get(f"/machines/{machine_id}")
    csrf = client.cookies.get("csrftoken")

    response = await client.post(
        f"/machines/{machine_id}/containers/immich_server/restart", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(f"/machines/{machine_id}/monitoring?")
    assert "container_action=restart" in response.headers["location"]
    assert celery_calls.names == ["app.tasks.jobs.run_container_action"]
    assert celery_calls[0][2] == {"action": "restart", "container": "immich_server"}


async def test_action_rejects_bad_input_without_connecting(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)
    await client.get(f"/machines/{machine_id}")
    csrf = client.cookies.get("csrftoken")

    response = await client.post(
        f"/machines/{machine_id}/containers/web/rm", data={"csrf_token": csrf}
    )

    assert response.status_code == 400
    assert celery_calls.names == []


async def test_action_requires_power_permission(client, login_as, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.MACHINE_MANAGE})
    await client.get(f"/machines/{machine_id}")
    csrf = client.cookies.get("csrftoken")

    response = await client.post(
        f"/machines/{machine_id}/containers/web/restart", data={"csrf_token": csrf}
    )

    assert response.status_code == 403
