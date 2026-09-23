"""HTTP-level tests for the Monitoring tab and its Services modal —
`tests/test_detail_tabs.py` already checks the "not gathered yet" empty
state (a brand-new machine with no samples); this file covers the
populated path, which needs its own DB rows first.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models.machine import Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_reachability_sample import MachineReachabilitySample
from app.db.models.machine_service import MachineService
from tests.test_web import _create_machine, _pin_host_key


async def _add_monitoring_sample(
    db_session_factory: async_sessionmaker[AsyncSession],
    machine_id: uuid.UUID,
    *,
    filesystems: list[dict[str, object]] | None = None,
    sensor_temps: list[dict[str, object]] | None = None,
    sensor_fans: list[dict[str, object]] | None = None,
    smart_disks: list[dict[str, object]] | None = None,
    cpu_energy_uj: int | None = None,
    gpu_power_watts: float | None = None,
) -> None:
    async with db_session_factory() as session:
        session.add(
            MachineMonitoringSample(
                machine_id=machine_id,
                sampled_at=datetime.now(UTC) - timedelta(minutes=1),
                cpu_percent=12.5,
                load1=0.5,
                load5=0.4,
                load15=0.3,
                ram_used_bytes=500_000_000,
                ram_total_bytes=1_000_000_000,
                network_io=[{"iface": "eth0", "rx_bytes": 1000, "tx_bytes": 500}],
                disk_io=[{"device": "sda", "read_bytes": 2000, "write_bytes": 1000}],
                filesystems=filesystems if filesystems is not None else [],
                failed_services_count=1,
                sensor_temps=sensor_temps if sensor_temps is not None else [],
                sensor_fans=sensor_fans if sensor_fans is not None else [],
                smart_disks=smart_disks if smart_disks is not None else [],
                cpu_energy_uj=cpu_energy_uj,
                gpu_power_watts=gpu_power_watts,
            )
        )
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.monitoring_updated_at = datetime.now(UTC)
        await session.commit()


async def _add_reachability_sample(
    db_session_factory: async_sessionmaker[AsyncSession],
    machine_id: uuid.UUID,
    *,
    reachable: bool = True,
    latency_ms: float | None = 4.2,
) -> None:
    async with db_session_factory() as session:
        session.add(
            MachineReachabilitySample(
                machine_id=machine_id,
                checked_at=datetime.now(UTC) - timedelta(minutes=1),
                reachable=reachable,
                latency_ms=latency_ms,
            )
        )
        await session.commit()


async def _add_service(
    db_session_factory: async_sessionmaker[AsyncSession],
    machine_id: uuid.UUID,
    *,
    unit: str,
    active_state: str,
) -> None:
    async with db_session_factory() as session:
        session.add(
            MachineService(
                machine_id=machine_id,
                unit=unit,
                load_state="loaded",
                active_state=active_state,
                sub_state=active_state,
                description="A test service",
            )
        )
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.services_updated_at = datetime.now(UTC)
        await session.commit()


async def test_monitoring_tab_renders_graphs_once_samples_exist(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="monitored")
    await _pin_host_key(db_session_factory, machine_id)
    await _add_monitoring_sample(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    # The graphs section itself is populated (services summary below it is
    # separately still "not gathered yet" — this test didn't add any
    # MachineService rows, only a monitoring sample).
    assert "No data in this range." not in response.text
    for title in ("CPU usage", "Load average", "Memory usage", "Network", "Disk I/O"):
        assert f'<h3 class="chart-card-title">{title}</h3>' in response.text
    assert "Current: 12.5%" in response.text


async def test_monitoring_tab_shows_condition_threshold_line(client, db_session_factory):
    from app.db.models.notification_condition import NotificationCondition
    from app.db.models.notification_rule import NotificationEventType, NotificationRule

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="thresholded")
    await _pin_host_key(db_session_factory, machine_id)
    await _add_monitoring_sample(db_session_factory, machine_id)

    async with db_session_factory() as db:
        rule = NotificationRule(
            name="cpu alert",
            enabled=True,
            event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
            conditions=[
                NotificationCondition(field="monitoring.cpu_percent", operator="gt", value="90")
            ],
        )
        db.add(rule)
        await db.commit()

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert 'class="chart-threshold"' in response.text
    assert "90" in response.text


async def test_monitoring_tab_time_range_selector_accepts_a_bad_value(
    client, db_session_factory
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="badrange")
    await _pin_host_key(db_session_factory, machine_id)
    await _add_monitoring_sample(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/monitoring?range_key=not-a-real-range")

    assert response.status_code == 200


async def test_services_modal_panel_lists_services_and_supports_search(
    client, db_session_factory
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="withservices")
    await _pin_host_key(db_session_factory, machine_id)
    await _add_service(db_session_factory, machine_id, unit="sshd.service", active_state="active")
    await _add_service(db_session_factory, machine_id, unit="foo.service", active_state="failed")

    response = await client.get(f"/machines/{machine_id}/services")
    assert response.status_code == 200
    assert "sshd.service" in response.text
    assert "foo.service" in response.text

    filtered = await client.get(f"/machines/{machine_id}/services", params={"svc_q": "sshd"})
    assert "sshd.service" in filtered.text
    assert "foo.service" not in filtered.text

    by_state = await client.get(f"/machines/{machine_id}/services", params={"svc_state": "failed"})
    assert "foo.service" in by_state.text
    assert "sshd.service" not in by_state.text


async def test_monitoring_tab_shows_filesystem_usage_graph(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="fs-monitored")
    await _pin_host_key(db_session_factory, machine_id)
    await _add_monitoring_sample(
        db_session_factory,
        machine_id,
        filesystems=[
            {"mount": "/", "size_bytes": 1000, "used_bytes": 300, "avail_bytes": 700,
             "use_percent": 30},
        ],
    )

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert '<h3 class="chart-card-title">Disk usage</h3>' in response.text
    assert "/: 300 B used of 1000 B (30%)" in response.text


async def test_overview_no_longer_shows_filesystems_table(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="fs-overview")
    await _pin_host_key(db_session_factory, machine_id)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.filesystems = [
            {"mount": "/", "size_bytes": 1000, "used_bytes": 300, "avail_bytes": 700,
             "use_percent": 30}
        ]
        machine.facts_updated_at = datetime.now(UTC)
        await session.commit()

    response = await client.get(f"/machines/{machine_id}")

    assert response.status_code == 200
    assert "<dt>Filesystems</dt>" not in response.text
    assert f"/machines/{machine_id}/monitoring" in response.text


async def test_monitoring_tab_shows_availability_section(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="available")
    await _add_reachability_sample(db_session_factory, machine_id, reachable=True, latency_ms=3.5)

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert '<h3 class="chart-card-title">Availability</h3>' in response.text
    assert "reachable" in response.text


async def test_monitoring_tab_shows_unreachable_status(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="unreachable-machine")
    await _add_reachability_sample(
        db_session_factory, machine_id, reachable=False, latency_ms=None
    )

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert "unreachable" in response.text


async def test_monitoring_tab_shows_hardware_panel_for_physical_machine(
    client, db_session_factory
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="physical-box")
    await _pin_host_key(db_session_factory, machine_id)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.is_physical = True
        await session.commit()
    await _add_monitoring_sample(
        db_session_factory,
        machine_id,
        sensor_temps=[{"name": "Package id 0", "celsius": 45.0}],
        sensor_fans=[{"name": "fan1", "rpm": 1200.0}],
        smart_disks=[{"device": "sda", "healthy": True}, {"device": "nvme0n1", "healthy": False}],
        gpu_power_watts=45.2,
    )

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert '<h3 class="chart-card-title">Temperature</h3>' in response.text
    assert '<h3 class="chart-card-title">Fans</h3>' in response.text
    assert '<h3 class="chart-card-title">GPU power</h3>' in response.text
    assert "Package id 0" in response.text
    assert "fan1" in response.text


async def test_monitoring_tab_hides_hardware_panel_for_vm(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="virtual-box")
    await _pin_host_key(db_session_factory, machine_id)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.is_physical = False
        await session.commit()
    await _add_monitoring_sample(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert '<h3 class="chart-card-title">Temperature</h3>' not in response.text


async def _set_machine(
    db_session_factory: async_sessionmaker[AsyncSession], machine_id: uuid.UUID, **fields: object
) -> None:
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        for key, value in fields.items():
            setattr(machine, key, value)
        await session.commit()


async def test_monitoring_tab_shows_docker_containers_table(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="docker-host")
    await _pin_host_key(db_session_factory, machine_id)
    await _add_monitoring_sample(db_session_factory, machine_id)
    await _set_machine(
        db_session_factory,
        machine_id,
        docker_status="ok",
        docker_containers=[
            {
                "name": "immich_server",
                "image": "ghcr.io/immich-app/immich-server:release",
                "state": "running",
                "status": "Up 10 days (healthy)",
                "health": "healthy",
                "ports": "0.0.0.0:2283->2283/tcp",
                "cpu_percent": 0.03,
                "mem_bytes": 789_000_000,
                "mem_limit_bytes": None,
                "net_rx_bytes": 1,
                "net_tx_bytes": 1,
            }
        ],
    )

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert '<h3 class="chart-card-title">All containers</h3>' in response.text
    assert "immich_server" in response.text
    assert "Healthy" in response.text
    assert "2283" in response.text


async def test_monitoring_tab_explains_docker_without_access(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="docker-denied")
    await _pin_host_key(db_session_factory, machine_id)
    await _add_monitoring_sample(db_session_factory, machine_id)
    await _set_machine(db_session_factory, machine_id, docker_status="no_access")

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert "can&#39;t reach the Docker daemon" in response.text


async def test_monitoring_tab_shows_smart_table_and_detail_drawer(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="smart-host")
    await _pin_host_key(db_session_factory, machine_id)
    await _add_monitoring_sample(db_session_factory, machine_id)
    await _set_machine(
        db_session_factory,
        machine_id,
        is_physical=True,
        smart_devices=[
            {
                "device": "/dev/nvme0n1",
                "model": "SAMSUNG MZVLB512HBJQ-000L7",
                "serial": "S4ENNX0T141660",
                "firmware": "5M2QEXF7",
                "capacity_bytes": 512_110_190_592,
                "type": "nvme",
                "rotation_rpm": None,
                "passed": True,
                "power_on_hours": 4203,
                "power_cycles": 1178,
                "temperature_c": 42,
                "attributes": [
                    {
                        "id": None, "name": "PercentageUsed", "value": None, "worst": None,
                        "threshold": None, "raw": "4", "failing": False,
                    }
                ],
            }
        ],
    )

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert "SAMSUNG MZVLB512HBJQ-000L7" in response.text
    assert "PASSED" in response.text
    assert "4 203 h" in response.text
    assert 'popovertarget="smart-drawer-1"' in response.text
    assert 'id="smart-drawer-1"' in response.text
    assert "PercentageUsed" in response.text


async def test_monitoring_tab_lists_services_with_usage(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="svc-usage")
    await _pin_host_key(db_session_factory, machine_id)
    await _add_monitoring_sample(db_session_factory, machine_id)
    await _add_service(db_session_factory, machine_id, unit="docker.service", active_state="active")
    async with db_session_factory() as session:
        from sqlalchemy import select

        query = select(MachineService).where(MachineService.machine_id == machine_id)
        row = (await session.execute(query)).scalar_one()
        row.cpu_percent = 0.01
        row.memory_bytes = 66_500_000
        row.memory_peak_bytes = 197_100_000
        await session.commit()

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert '<h3 class="chart-card-title">systemd services</h3>' in response.text
    assert "<code>docker</code>" in response.text
    assert "63.4 MB" in response.text
    assert "Total: 1 | Failed: 0" in response.text
