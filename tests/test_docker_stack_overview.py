"""Docker pages made easier to read: a one-shot container that finished
(a migration, an import: restart policy "no"/"on-failure", exit code 0)
counts as done instead of making its stack look half-stopped; stacks show
their services as state chips; container tables are grouped by stack."""

from __future__ import annotations

import uuid
from typing import Any

from app.db.models.machine import Machine
from app.services import docker_inventory_snapshot as inventory_snapshot
from tests.test_docker_web_support import INVENTORY_TASK, inventory_answer, make_docker_machine
from tests.test_update_history import _api_token

MIGRATE = {
    "name": "site-migrate-1",
    "compose_project": "site",
    "compose_service": "migrate",
    "state": "exited",
    "status": "Exited (0) 2 days ago",
    "image": "app:local",
}


def _inspected(
    name: str, service: str, policy: str, state: str, code: int | None
) -> dict[str, Any]:
    return {
        "name": name,
        "compose_project": "site",
        "compose_service": service,
        "state": state,
        "running": state == "running",
        "exit_code": code,
        "restart_policy": policy,
    }


async def _machine_with_migrate(db_session_factory: Any) -> uuid.UUID:
    """The support machine ("web" running in stack site, "worker" exited 1
    outside any stack) plus site's migrate job, finished; the stored
    inventory knows migrate runs once."""
    machine_id = await make_docker_machine(db_session_factory)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.docker_containers = [*(machine.docker_containers or []), MIGRATE]
        inventory_snapshot.store(
            machine,
            {
                "compose": [{"name": "site", "status": "exited(1), running(1)"}],
                "containers": [
                    _inspected("web", "web", "unless-stopped", "running", None),
                    _inspected("site-migrate-1", "migrate", "no", "exited", 0),
                ],
            },
            inventory_snapshot.SECTIONS,
        )
        await session.commit()
    return machine_id


def test_the_snapshot_remembers_one_shot_containers() -> None:
    machine = Machine(name="m")
    inventory_snapshot.store(
        machine,
        {
            "containers": [
                _inspected("a", "a", "no", "exited", 0),
                _inspected("b", "b", "on-failure", "running", None),
                _inspected("c", "c", "always", "running", None),
                # Without the policy (an older reader): never a one-shot.
                {"name": "d"},
            ]
        },
        inventory_snapshot.SECTIONS,
    )
    assert (machine.docker_inventory or {})["one_shot"] == ["a", "b"]


async def test_fleet_stacks_count_a_finished_migration_as_done(
    client: Any, db_session_factory: Any
) -> None:
    await _machine_with_migrate(db_session_factory)

    page = (await client.get("/docker/stacks")).text

    assert "partly running" not in page
    assert "1 of 1 services running" in page
    assert "1 one-shot finished" in page
    assert 'class="service-chip service-chip-completed"' in page

    headers = await _api_token(client)
    data = (
        await client.get("/api/v1/docker/stacks", headers=headers)
    ).json()
    [site] = [row for row in data["stacks"] if row["name"] == "site"]
    assert site["state"] == "running"
    assert (site["services"], site["completed"]) == (1, 1)
    assert {c["name"]: c["row_state"] for c in site["containers"]} == {
        "web": "running",
        "site-migrate-1": "completed",
    }


async def test_containers_are_grouped_by_stack(client: Any, db_session_factory: Any) -> None:
    machine_id = await _machine_with_migrate(db_session_factory)

    fleet = (await client.get("/docker/containers")).text
    own = (await client.get(f"/machines/{machine_id}/docker")).text

    for page in (fleet, own):
        assert 'class="group-row"' in page
        assert "stack site" in page
        assert "Containers outside any stack" in page
        assert 'data-row-state="completed" class="row-muted"' in page
        assert "finished" in page
    # Sorted by anything else, the fleet list is flat again.
    flat = (await client.get("/docker/containers?sort=name")).text
    assert 'class="group-row"' not in flat

    headers = await _api_token(client)
    data = (
        await client.get("/api/v1/docker/containers", headers=headers)
    ).json()
    assert {c["name"]: c["row_state"] for c in data["containers"]}["site-migrate-1"] == "completed"
    assert data["state_counts"]["completed"] == 1
    assert data["stacks"][f"{machine_id}/site"]["state"] == "running"


async def test_projects_panel_shows_services_as_chips_and_a_menu(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    answer = inventory_answer()
    answer["inventory"]["containers"].append(
        {**_inspected("site-migrate-1", "migrate", "no", "exited", 0), "compose_config_files": []}
    )
    celery_calls.result_for[INVENTORY_TASK] = answer
    base = f"/machines/{machine_id}/docker"

    panel = (await client.get(f"{base}/stacks/panel")).text

    assert 'class="service-chip service-chip-running"' in panel
    assert 'class="service-chip service-chip-completed"' in panel
    assert ">running</span>" in panel
    assert f'formaction="{base}/projects/site/down"' in panel
    assert 'popover class="row-menu"' in panel

    headers = await _api_token(client)
    [site] = (
        await client.get(f"/api/v1/machines/{machine_id}/docker/projects",
                         headers=headers)
    ).json()
    assert site["summary"]["state"] == "running"
    assert site["summary"]["completed"] == 1
