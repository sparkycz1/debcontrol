"""Docker mode of the Logs tab: command building (`app.ssh.logs`), the web
route's dispatch, and the line classification the viewer renders
(`app.web.log_lines`)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models.machine import Machine
from app.ssh.logs import LogAccessError, build_docker_logs_command, is_container_name_valid
from app.web.log_lines import parse_log_lines
from tests.test_onboarding import _make_machine


@pytest.mark.parametrize("name", ["immich_server", "web-1", "a.b", "X9"])
def test_valid_container_names(name):
    assert is_container_name_valid(name)


@pytest.mark.parametrize("name", ["", "-rm", "a b", "x;rm -rf /", "$(id)", "_lead", "a/b"])
def test_invalid_container_names(name):
    assert not is_container_name_valid(name)


def test_docker_logs_command_rejects_an_invalid_name():
    with pytest.raises(LogAccessError):
        build_docker_logs_command(container="x;id", lines=10, search="", since="", until="")


def test_docker_logs_command_tails_and_quotes():
    command = build_docker_logs_command(
        container="web", lines=99999, search="", since="-1h; id", until=""
    )

    assert "$D logs --timestamps --since '-1h; id' --tail 5000 web 2>&1" in command
    assert "sudo -n -l" in command


def test_docker_logs_command_search_filters_the_whole_log():
    command = build_docker_logs_command(
        container="web", lines=50, search="it's", since="", until=""
    )

    assert "--tail" not in command
    assert "| grep -F -- 'it'\"'\"'s' | tail -n 50" in command


def test_parse_log_lines_levels_and_highlight():
    lines = parse_log_lines("ok line\nERROR: boom\nwarning: x\nterrorist fine", "boom")

    assert [line.level for line in lines] == [None, "error", "warn", None]
    assert lines[1].segments == [("ERROR: ", False), ("boom", True)]


def test_parse_log_lines_empty():
    assert parse_log_lines(None) == []
    assert parse_log_lines("") == []


async def _with_containers(
    db_session_factory: async_sessionmaker[AsyncSession], machine_id: uuid.UUID
) -> None:
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.docker_status = "ok"
        machine.docker_containers = [
            {"name": "old", "state": "exited", "health": None},
            {"name": "immich_server", "state": "running", "health": "healthy"},
        ]
        await session.commit()


async def test_docker_source_defaults_to_the_first_running_container(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)
    await _with_containers(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/logs", params={"source": "docker"})

    assert response.status_code == 200
    assert celery_calls.names == ["app.tasks.jobs.view_machine_docker_logs"]
    assert celery_calls[0][2]["container"] == "immich_server"
    assert '<option value="immich_server" selected>' in response.text.replace("\n", "")


async def test_docker_source_uses_the_chosen_container(client, db_session_factory, celery_calls):
    machine_id = await _make_machine(db_session_factory)
    await _with_containers(db_session_factory, machine_id)

    await client.get(
        f"/machines/{machine_id}/logs",
        params={"source": "docker", "container": "old", "search": "err"},
    )

    assert celery_calls[0][2]["container"] == "old"
    assert celery_calls[0][2]["search"] == "err"


async def test_docker_source_without_known_containers_does_not_connect(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)

    response = await client.get(f"/machines/{machine_id}/logs", params={"source": "docker"})

    assert response.status_code == 200
    assert celery_calls.names == []
    assert "discovered by the Monitoring sample" in response.text


async def test_file_source_without_a_path_does_not_connect(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)

    response = await client.get(f"/machines/{machine_id}/logs", params={"source": "file"})

    assert response.status_code == 200
    assert celery_calls.names == []
