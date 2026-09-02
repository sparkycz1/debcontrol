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
from app.db.models.machine_service import MachineService
from tests.test_web import _create_machine, _pin_host_key


async def _add_monitoring_sample(
    db_session_factory: async_sessionmaker[AsyncSession], machine_id: uuid.UUID
) -> None:
    async with db_session_factory() as session:
        session.add(
            MachineMonitoringSample(
                machine_id=machine_id,
                sampled_at=datetime.now(UTC) - timedelta(minutes=1),
                cpu_percent=12.5,
                ram_used_bytes=500_000_000,
                ram_total_bytes=1_000_000_000,
                disks=[{"mount": "/", "use_percent": 40}],
                failed_services_count=1,
            )
        )
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.monitoring_updated_at = datetime.now(UTC)
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
    assert "<h2>RAM</h2>" in response.text
    assert "<h2>Disk usage</h2>" in response.text
    assert "12.5" in response.text


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
