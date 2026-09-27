"""The Fleet page (`/fleet`), its API twin, and the row builder
(`app.services.fleet_overview`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.role import Permission
from app.services.fleet_overview import build_fleet_row, level_for
from tests.test_api_v1_extended import _api_token
from tests.test_monitoring_web import _add_monitoring_sample
from tests.test_onboarding import _make_machine


def _machine(**fields: object) -> Machine:
    machine = Machine(
        id=uuid.uuid4(), name="box", ip_address="10.0.0.1", port=22, username="u",
        auth_method=AuthMethod.PASSWORD,
    )
    for key, value in fields.items():
        setattr(machine, key, value)
    return machine


def test_level_for_thresholds():
    assert level_for(None) == "unknown"
    assert level_for(10) == "ok"
    assert level_for(80) == "warn"
    assert level_for(95) == "danger"
    assert level_for(72, (70.0, 85.0)) == "warn"


def test_row_picks_fullest_disk_and_hottest_sensor():
    sample = MachineMonitoringSample(
        machine_id=uuid.uuid4(),
        sampled_at=datetime.now(UTC),
        cpu_percent=12.0,
        ram_used_bytes=500,
        ram_total_bytes=1000,
        filesystems=[
            {"mount": "/", "use_percent": 40},
            {"mount": "/srv", "use_percent": 93},
        ],
        sensor_temps=[{"name": "a", "celsius": 45.0}, {"name": "b", "celsius": 61.0}],
    )

    row = build_fleet_row(_machine(is_reachable=True), sample)

    assert row.ram_percent == 50.0
    assert (row.disk_percent, row.disk_mount) == (93.0, "/srv")
    assert row.temperature_c == 61.0
    assert row.level == "danger"  # the 93% disk


def test_row_offline_or_container_problem_is_danger():
    down = build_fleet_row(_machine(is_reachable=False), None)
    unhealthy = build_fleet_row(
        _machine(
            is_reachable=True,
            docker_status="ok",
            docker_containers=[{"name": "x", "state": "running", "health": "unhealthy"}],
        ),
        None,
    )

    assert down.level == "danger"
    assert unhealthy.level == "danger"
    assert (unhealthy.containers_running, unhealthy.containers_total) == (1, 1)


async def test_fleet_page_lists_machines_with_readings(client, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    await _add_monitoring_sample(db_session_factory, machine_id)

    response = await client.get("/dashboard")
    cards = await client.get("/fleet/cards")
    moved = await client.get("/fleet", follow_redirects=False)

    assert response.status_code == 200
    assert 'id="fleet"' in response.text
    assert f'href="/machines/{machine_id}/monitoring"' in response.text
    assert "12.5%" in response.text  # the sample's CPU
    assert f'href="/machines/{machine_id}/monitoring"' in cards.text  # the 60 s refresh
    assert moved.status_code == 308
    assert moved.headers["location"] == "/dashboard#fleet"


async def test_fleet_page_requires_machine_view(client, login_as):
    await login_as(client, permissions={Permission.AUDIT_VIEW})

    response = await client.get("/fleet/cards")

    assert response.status_code == 403


async def test_fleet_api(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await _make_machine(db_session_factory)
    await _add_monitoring_sample(db_session_factory, machine_id)

    response = await client.get("/api/v1/fleet", headers=headers)

    assert response.status_code == 200
    rows = {row["machine_id"]: row for row in response.json()}
    assert rows[str(machine_id)]["cpu_percent"] == 12.5
