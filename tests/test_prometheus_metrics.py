"""`GET /api/v1/metrics` — the fleet's stored state in Prometheus text
format (`app.services.prometheus_metrics`)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from httpx2 import AsyncClient

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token


async def test_metrics_need_a_token(client: AsyncClient) -> None:
    response = await client.get("/api/v1/metrics")

    assert response.status_code == 401


async def test_metrics_describe_machines_and_checks(
    client: AsyncClient, db_session_factory: Any
) -> None:
    machine_id = await _add_machine(
        db_session_factory,
        name='web "one"',
        is_reachable=True,
        upgradable_count=7,
        security_upgradable_count=2,
        reboot_required=True,
        failed_units=["nginx.service"],
        uptime_seconds=3600,
    )
    await _add_machine(db_session_factory, name="silent", ip_address="10.0.0.8")
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        db.add(
            MachineMonitoringSample(
                machine_id=machine_id,
                sampled_at=now,
                cpu_percent=12.5,
                load1=0.4,
                ram_used_bytes=1024,
                ram_total_bytes=4096,
                filesystems=[
                    {"mount": "/", "use_percent": 41},
                    {"mount": "/var", "use_percent": 77},
                ],
                failed_services_count=1,
            )
        )
        db.add(
            EndpointCheck(
                name="site",
                kind="http",
                target="https://example.com",
                last_ok=False,
                last_latency_ms=250.0,
                cert_expires_at=now,
            )
        )
        db.add(EndpointCheck(name="off", kind="tcp", target="example.com:22", enabled=False))
        await db.commit()
    headers = await _api_token(client)

    response = await client.get("/api/v1/metrics", headers=headers)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain; version=0.0.4")
    text = response.text
    labels = r'machine="web \"one\"",group=""'
    for line in (
        "debcontrol_machines 2",
        f"debcontrol_machine_up{{{labels}}} 1",
        f"debcontrol_machine_pending_updates{{{labels}}} 7",
        f"debcontrol_machine_pending_security_updates{{{labels}}} 2",
        f"debcontrol_machine_reboot_required{{{labels}}} 1",
        f"debcontrol_machine_failed_units{{{labels}}} 1",
        f"debcontrol_machine_cpu_percent{{{labels}}} 12.5",
        f"debcontrol_machine_memory_percent{{{labels}}} 25.0",
        f'debcontrol_machine_disk_percent{{{labels},mount="/var"}} 77.0',
        f"debcontrol_machine_uptime_seconds{{{labels}}} 3600",
        'debcontrol_check_up{check="site",kind="http"} 0',
        'debcontrol_check_latency_seconds{check="site",kind="http"} 0.25',
        "# TYPE debcontrol_machine_up gauge",
    ):
        assert line in text, line
    # Unknown values are left out, not reported as zero.
    assert 'debcontrol_machine_up{machine="silent"' not in text
    assert 'debcontrol_machine_cpu_percent{machine="silent"' not in text
    # A disabled check is not exported.
    assert 'check="off"' not in text
    # Every sample line is "name{labels} value" or "name value".
    for line in text.strip().splitlines():
        assert line.startswith("#") or len(line.rsplit(" ", 1)) == 2, line
