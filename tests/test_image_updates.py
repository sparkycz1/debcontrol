"""Docker image update detection (`app.ssh.image_updates`), the on-demand
route, and the `docker.image_updates_count` condition field."""

from __future__ import annotations

import pytest

from app.db.models.machine import AuthMethod, Machine
from app.services.condition_fields import evaluate_condition
from app.ssh.image_updates import ImageCheckError, count_updates, parse_image_update_output
from tests.test_docker_logs import _with_containers
from tests.test_monitoring_web import _add_monitoring_sample
from tests.test_onboarding import _make_machine

OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64


def test_parse_update_current_and_unknown():
    raw = "\n".join(
        [
            f"nginx:latest\t{NEW}\tnginx@{OLD}",
            f"redis:7\t{NEW}\tredis@{NEW} docker.io/library/redis@{OLD}",
            f"myapp:dev\t{NEW}\t",
            f"postgres@{OLD}\t{NEW}\tpostgres@{OLD}",
            "private/x:1\t\tprivate/x@" + OLD,
        ]
    )

    statuses = parse_image_update_output(raw)

    assert statuses == {
        "nginx:latest": "update",
        "redis:7": "current",
        "myapp:dev": "unknown",
        f"postgres@{OLD}": "unknown",
        "private/x:1": "unknown",
    }
    assert count_updates(statuses) == 1


def test_parse_no_access():
    with pytest.raises(ImageCheckError):
        parse_image_update_output("@@NOACCESS\n")


def test_condition_field():
    machine = Machine(
        name="m", ip_address="10.0.0.1", port=22, username="u", auth_method=AuthMethod.PASSWORD
    )
    assert not evaluate_condition("docker.image_updates_count", "eq", "0", machine, None, None)
    machine.docker_image_updates = {"nginx:latest": "update", "redis:7": "current"}
    assert evaluate_condition("docker.image_updates_count", "gt", "0", machine, None, None)


async def test_check_button_dispatches_and_redirects(client, db_session_factory, celery_calls):
    machine_id = await _make_machine(db_session_factory)
    await client.get(f"/machines/{machine_id}")
    csrf = client.cookies.get("csrftoken")

    response = await client.post(
        f"/machines/{machine_id}/docker/check-images", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert "images_checked=1" in response.headers["location"]
    assert celery_calls.names == ["app.tasks.jobs.check_machine_image_updates"]


async def test_table_shows_update_badge(client, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    await _add_monitoring_sample(db_session_factory, machine_id)
    await _with_containers(db_session_factory, machine_id)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.docker_containers = [
            {"name": "web", "state": "running", "health": None, "image": "nginx:latest"}
        ]
        machine.docker_image_updates = {"nginx:latest": "update"}
        await session.commit()

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert "update available" in response.text
    assert f"/machines/{machine_id}/docker/check-images" in response.text
