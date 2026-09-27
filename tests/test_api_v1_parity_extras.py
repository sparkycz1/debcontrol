"""API parity additions: operational settings writes, audit-chain
verification, monitoring history/refresh and a single update run."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from app.core.app_settings import get_or_create_app_settings
from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.role import Permission
from tests.test_api_v1_extended import _api_token, _create_machine


async def test_settings_patch_validates_saves_and_audits(client, db_session_factory):
    headers = await _api_token(client)

    bad = await client.patch(
        "/api/v1/settings",
        json={"ssh_connect_timeout": 0, "audit_log_retention_days": 30},
        headers=headers,
    )
    assert bad.status_code == 422
    assert "between 1 and 300" in bad.json()["detail"]

    unknown = await client.patch(
        "/api/v1/settings", json={"smtp_password": "x"}, headers=headers
    )
    assert unknown.status_code == 422

    ok = await client.patch(
        "/api/v1/settings",
        json={
            "ssh_connect_timeout": 20,
            "monitoring_interval_seconds": 300,
            "audit_log_retention_days": None,
            "ai_daily_token_limit": 5000,
        },
        headers=headers,
    )
    assert ok.status_code == 200, ok.text
    # Beat follows interval changes live now — nothing needs a restart.
    assert ok.json()["needs_restart"] == []

    read = (await client.get("/api/v1/settings", headers=headers)).json()
    assert read["ssh_connect_timeout"] == 20
    assert read["ai_daily_token_limit"] == 5000

    async with db_session_factory() as session:
        app_settings = await get_or_create_app_settings(session)
        assert app_settings.monitoring_interval_seconds == 300
        actions = set((await session.execute(select(AuditLogEntry.action))).scalars().all())
    assert {"settings.background_checks.update", "settings.ai_limits.update"} <= actions


async def test_settings_patch_needs_manage_permission(client, login_as):
    await login_as(client, permissions={Permission.SETTINGS_VIEW}, api_access_enabled=True)
    headers = await _api_token(client)
    response = await client.patch(
        "/api/v1/settings", json={"ssh_connect_timeout": 20}, headers=headers
    )
    assert response.status_code == 403


async def test_audit_verify_via_api(client):
    headers = await _api_token(client)
    response = await client.post("/api/v1/audit/verify", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["checked"] >= 1


async def test_monitoring_history_via_api(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "api-monitoring")
    async with db_session_factory() as session:
        session.add(
            MachineMonitoringSample(
                machine_id=uuid.UUID(machine_id),
                sampled_at=datetime.now(UTC),
                cpu_percent=42.0,
                ram_used_bytes=1,
                ram_total_bytes=4,
            )
        )
        await session.commit()

    response = await client.get(
        f"/api/v1/machines/{machine_id}/monitoring?range_key=24h", headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["range_key"] == "24h"
    assert body["monitoring"]["latest_cpu_percent"] == 42.0
    assert body["monitoring"]["sample_count"] == 1
    assert "uptime_percent" in body["availability"]

    fallback = await client.get(
        f"/api/v1/machines/{machine_id}/monitoring?range_key=bogus", headers=headers
    )
    assert fallback.json()["range_key"] == "1h"


async def test_monitoring_refresh_via_api(client, celery_calls):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "api-monitoring-refresh")
    response = await client.post(
        f"/api/v1/machines/{machine_id}/monitoring/refresh", headers=headers
    )
    assert response.status_code == 200, response.text
    assert "app.tasks.jobs.sample_machine_monitoring" in celery_calls.names


async def test_single_update_run_via_api(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "api-run")
    other_id = await _create_machine(client, headers, "api-run-other")
    async with db_session_factory() as session:
        run = MachineUpdateRun(
            machine_id=uuid.UUID(machine_id),
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
            output="done",
        )
        session.add(run)
        await session.commit()
        run_id = run.id

    response = await client.get(
        f"/api/v1/machines/{machine_id}/update-runs/{run_id}", headers=headers
    )
    assert response.status_code == 200
    assert response.json()["output"] == "done"

    # A run id under the wrong machine is a 404, not a leak.
    wrong = await client.get(f"/api/v1/machines/{other_id}/update-runs/{run_id}", headers=headers)
    assert wrong.status_code == 404
