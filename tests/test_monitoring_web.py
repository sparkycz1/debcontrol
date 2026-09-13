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
    assert "<h2>CPU</h2>" in response.text
    assert "<h3>Load average</h3>" in response.text
    assert "<h2>Memory</h2>" in response.text
    assert "<h2>Network</h2>" in response.text
    assert "<h2>Disk</h2>" in response.text
    assert "12.5" in response.text
    assert "eth0" in response.text
    assert "sda" in response.text


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
    assert "trend-chart-threshold" in response.text
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
    assert "<h3>Usage</h3>" in response.text
    assert "<code>/</code>" in response.text
    assert "30%" in response.text


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
    assert "<h2>Availability</h2>" in response.text
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
