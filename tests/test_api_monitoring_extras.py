"""`GET /api/v1/machines/{id}/services` and `/hardware` — the REST
counterparts of the Monitoring tab's services table, S.M.A.R.T. table,
Docker table and hardware readings."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.db.models.machine import Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_service import MachineService
from tests.test_api_v1_extended import _api_token, _create_machine


async def test_services_api_includes_usage(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "api-services")
    async with db_session_factory() as session:
        session.add(
            MachineService(
                machine_id=uuid.UUID(machine_id), unit="docker.service", load_state="loaded",
                active_state="active", sub_state="running", description="Docker",
                cpu_percent=0.5, memory_bytes=1024,
            )
        )
        await session.commit()

    response = await client.get(f"/api/v1/machines/{machine_id}/services", headers=headers)

    assert response.status_code == 200
    (service,) = response.json()
    assert service["unit"] == "docker.service"
    assert service["cpu_percent"] == 0.5
    assert service["memory_bytes"] == 1024


async def test_hardware_api(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "api-hardware")
    async with db_session_factory() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        assert machine is not None
        machine.is_physical = True
        machine.smart_devices = [{"device": "/dev/sda", "passed": True, "attributes": []}]
        machine.docker_status = "ok"
        machine.docker_containers = [{"name": "web", "state": "running"}]
        session.add(
            MachineMonitoringSample(
                machine_id=machine.id,
                sampled_at=datetime.now(UTC),
                sensor_temps=[{"name": "k10temp Tctl", "celsius": 48.0}],
                gpus=[{"id": "card0", "name": "AMD Radeon RX 550", "power_watts": 3.2}],
            )
        )
        await session.commit()

    response = await client.get(f"/api/v1/machines/{machine_id}/hardware", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["smart_devices"][0]["device"] == "/dev/sda"
    assert body["docker_containers"][0]["name"] == "web"
    assert body["sensor_temps"][0]["celsius"] == 48.0
    assert body["gpus"][0]["name"] == "AMD Radeon RX 550"


async def test_hardware_api_requires_a_token(client):
    response = await client.get(f"/api/v1/machines/{uuid.uuid4()}/hardware")

    assert response.status_code == 401
