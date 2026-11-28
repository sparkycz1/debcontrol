"""Machine health (`app.services.machine_health`): what each category finds,
how snoozes and reachability shape the status, the notifications on a
change, the fleet score, and the web and REST routes around it."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.app_settings import AppSettings
from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_health_snooze import MachineHealthSnooze
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.notification_log import NotificationDeliveryStatus
from app.db.models.notification_rule import NotificationEventType, NotificationRule
from app.services import machine_health
from app.services import notifications as notifications_module
from app.services.machine_health import Finding, Thresholds
from tests.test_api_v1_extended import _api_token

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def _machine(name: str = "web1", **kwargs: Any) -> Machine:
    return Machine(
        name=name,
        ip_address="10.0.0.1",
        port=22,
        username="root",
        auth_method=AuthMethod.PASSWORD,
        **kwargs,
    )


def _sample(machine_id: Any = None, minutes_ago: int = 0, **kwargs: Any) -> MachineMonitoringSample:
    return MachineMonitoringSample(
        machine_id=machine_id or uuid.uuid4(),
        sampled_at=NOW - timedelta(minutes=minutes_ago),
        **kwargs,
    )


def _keys(findings: list[Finding]) -> dict[str, str]:
    return {f.key: f.severity for f in findings}


def _capture_webhook(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    posted: list[str] = []

    async def _fake_post(*args: Any) -> tuple[NotificationDeliveryStatus, None]:
        posted.append(args[1])
        return NotificationDeliveryStatus.SENT, None

    monkeypatch.setattr(notifications_module, "_send_webhook", _fake_post)
    return posted


def _rule() -> NotificationRule:
    return NotificationRule(
        name="health",
        enabled=True,
        event_types=[
            NotificationEventType.HEALTH_DEGRADED.value,
            NotificationEventType.HEALTH_RECOVERED.value,
        ],
        delivery_channel="webhook",
        webhook_url="https://hooks.example.com/abc",
    )


# --- Evaluating ---------------------------------------------------------------


def test_readings_turn_into_findings_by_threshold() -> None:
    machine = _machine(
        disk_forecast={"/data": {"days_until_full": 5}, "/": {"days_until_full": 1}},
        failed_units=["nginx.service"],
        security_upgradable_count=3,
        upgradable_count=10,
        reboot_required=True,
        zfs_pools=[{"name": "tank", "health": "DEGRADED"}],
    )
    samples = [
        _sample(
            cpu_percent=97,
            ram_used_bytes=90,
            ram_total_bytes=100,
            filesystems=[
                {"mount": "/", "use_percent": 96},
                {"mount": "/boot", "use_percent": 50},
            ],
            # Only the CPU's own sensor counts: a hot NVMe controller is
            # the disks' business (SMART), not the CPU's.
            sensor_temps=[{"name": "cpu", "celsius": 92}, {"name": "nvme Sensor 2", "celsius": 99}],
            smart_disks=[{"device": "/dev/sda", "healthy": False}],
        ),
        _sample(minutes_ago=1, cpu_percent=90),
        _sample(minutes_ago=2, cpu_percent=95),
        # Beyond the three samples CPU is averaged over.
        _sample(minutes_ago=3, cpu_percent=0),
    ]
    findings = machine_health.evaluate(machine, samples, Thresholds(), now=NOW)
    assert _keys(findings) == {
        "cpu.usage": "warning",  # (97 + 90 + 95) / 3 = 94
        "cpu.temperature": "warning",
        "memory.usage": "warning",
        "storage.fs:/": "critical",
        # "/" is already full: its forecast is not listed twice.
        "storage.forecast:/data": "warning",
        "disks.smart:/dev/sda": "critical",
        "disks.zfs:tank": "warning",
        "services.unit:nginx.service": "warning",
        "updates.security": "warning",
        "updates.reboot": "warning",
        "updates.pending": "info",
    }
    cpu = next(f for f in findings if f.key == "cpu.usage")
    assert cpu.params == {"percent": 94}
    assert machine_health.finding_text(cpu) == "CPU use 94 % (last three samples)"
    assert machine_health.finding_text(cpu, "cs") == "Využití CPU 94 % (poslední tři vzorky)"


def test_custom_thresholds_and_a_quiet_machine() -> None:
    machine = _machine()
    samples = [_sample(cpu_percent=70, ram_used_bytes=10, ram_total_bytes=100)]
    assert machine_health.evaluate(machine, samples, Thresholds(), now=NOW) == []
    strict = Thresholds(cpu_warn=60, cpu_critical=65)
    assert _keys(machine_health.evaluate(machine, samples, strict, now=NOW)) == {
        "cpu.usage": "critical"
    }


def test_thresholds_come_from_settings() -> None:
    settings = AppSettings(id=1, health_cpu_warn_percent=50, health_disk_full_critical_days=3)
    th = Thresholds.from_settings(settings)
    assert th.cpu_warn == 50 and th.disk_full_critical_days == 3


def test_a_finding_round_trips_and_unknown_ones_are_dropped() -> None:
    finding = Finding("cpu.usage", "cpu", "warning", "cpu_high", {"percent": 90}, "monitoring")
    assert Finding.from_dict(finding.as_dict()) == finding
    assert Finding.from_dict({"key": "x"}) is None
    assert Finding.from_dict({**finding.as_dict(), "severity": "bogus"}) is None


# --- The status ---------------------------------------------------------------


def _stored(machine: Machine, *findings: Finding, error: str | None = None) -> None:
    machine.health = {
        "at": NOW.isoformat(),
        "findings": [f.as_dict() for f in findings],
        "error": error,
    }


WARN = Finding("storage.fs:/", "storage", "warning", "filesystem_full",
               {"mount": "/", "percent": 90}, "monitoring")
CRIT = Finding("storage.fs:/", "storage", "critical", "filesystem_full",
               {"mount": "/", "percent": 97}, "monitoring")


def test_status_snoozes_and_reachability() -> None:
    machine = _machine(id=uuid.uuid4())
    assert machine_health.build_view(machine, [], NOW).status is None

    _stored(machine, WARN)
    view = machine_health.build_view(machine, [], NOW)
    assert view.status == "warning" and view.category_status("storage") == "warning"

    snooze = MachineHealthSnooze(
        machine_id=machine.id, finding_key=WARN.key, severity="warning",
        until=NOW + timedelta(hours=1),
    )
    view = machine_health.build_view(machine, [snooze], NOW)
    assert view.status == "ok" and [f.key for f, _s in view.snoozed] == [WARN.key]

    # Its time passed.
    assert machine_health.build_view(machine, [snooze], NOW + timedelta(hours=2)).status == (
        "warning"
    )

    # It got worse than when it was snoozed.
    _stored(machine, CRIT)
    assert machine_health.build_view(machine, [snooze], NOW).status == "critical"

    # Unreachable is critical, and the SSH error that follows from it is left out.
    _stored(machine, error="timed out")
    assert [f.key for f in machine_health.effective_findings(machine)] == ["connection.ssh"]
    machine.is_reachable = False
    view = machine_health.build_view(machine, [], NOW)
    assert view.status == "critical"
    assert [f.key for f in view.active] == ["connection.unreachable"]


def test_notifications_only_on_real_changes() -> None:
    assert not machine_health.degraded(None, "critical")  # first evaluation
    assert machine_health.degraded("ok", "warning")
    assert machine_health.degraded("warning", "critical")
    assert not machine_health.degraded("critical", "warning")
    assert not machine_health.degraded("ok", "info")
    assert machine_health.recovered("warning", "ok")
    assert machine_health.recovered("critical", "info")
    assert not machine_health.recovered("info", "ok")


def test_fleet_score() -> None:
    assert machine_health.score_of({"ok": 0}) is None
    assert machine_health.score_of({"ok": 2, "info": 1, "warning": 0, "critical": 0}) == 100
    assert machine_health.score_of({"ok": 1, "info": 0, "warning": 2, "critical": 1}) == 50


# --- Refreshing, with the database --------------------------------------------


async def test_refresh_stores_notifies_and_drops_stale_snoozes(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted = _capture_webhook(monkeypatch)
    async with db_session_factory() as db:
        machine = _machine()
        db.add_all([machine, _rule()])
        await db.commit()
        db.add(_sample(machine.id, filesystems=[{"mount": "/", "use_percent": 50}]))
        await db.commit()

        # First evaluation: stored, never notified.
        await machine_health.refresh(db, machine)
        assert machine.health_status == "ok" and posted == []

        db.add(_sample(machine.id, minutes_ago=-1, filesystems=[{"mount": "/", "use_percent": 91}]))
        await db.commit()
        await machine_health.refresh(db, machine)
        assert machine.health_status == "warning"
        assert posted == ["machine.health_degraded"]

        # Snoozing is silent and lowers the status.
        await machine_health.snooze(db, machine, "storage.fs:/", hours=None, by="alice")
        await db.commit()
        assert machine.health_status == "ok"
        await machine_health.refresh(db, machine)
        assert posted == ["machine.health_degraded"]

        # Gone: the snooze is dropped, nothing to recover from (it was snoozed).
        db.add(_sample(machine.id, minutes_ago=-2, filesystems=[{"mount": "/", "use_percent": 40}]))
        await db.commit()
        await machine_health.refresh(db, machine)
        assert (await db.execute(select(MachineHealthSnooze))).scalars().all() == []
        assert posted == ["machine.health_degraded"]

        # A failed sample keeps what was found and adds the SSH error:
        # informational once, critical when it fails again.
        await machine_health.refresh(db, machine, error="Connection refused")
        assert machine.health_status == "info"
        assert posted == ["machine.health_degraded"]
        await machine_health.refresh(db, machine, error="Connection refused")
        assert machine.health_status == "critical"
        assert posted == ["machine.health_degraded", "machine.health_degraded"]

        # Unreachable on top: no health notification of its own.
        machine.is_reachable = False
        await db.commit()
        await machine_health.refresh_status_only(db, machine)
        assert machine.health_status == "critical"
        machine.is_reachable = True
        await db.commit()
        db.add(_sample(machine.id, minutes_ago=-3, filesystems=[{"mount": "/", "use_percent": 40}]))
        await db.commit()
        await machine_health.refresh(db, machine)
        assert machine.health_status == "ok"
        assert posted[-1] == "machine.health_recovered"


async def test_snoozing_an_unknown_problem_fails(db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        machine = _machine()
        db.add(machine)
        await db.commit()
        _stored(machine, WARN)
        with pytest.raises(machine_health.UnknownFindingError):
            await machine_health.snooze(db, machine, "cpu.usage", hours=1, by="a")
        with pytest.raises(ValueError):
            await machine_health.snooze(db, machine, WARN.key, hours=0, by="a")
        assert not await machine_health.unsnooze(db, machine, WARN.key)
        machine.is_reachable = False
        with pytest.raises(ValueError):
            await machine_health.snooze(db, machine, "connection.unreachable", hours=1, by="a")


async def test_fleet_health_and_worst_machines(db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        good, bad, worse = _machine("good"), _machine("bad"), _machine("worse")
        for machine, finding in ((good, None), (bad, WARN), (worse, CRIT)):
            if finding:
                _stored(machine, finding)
            else:
                _stored(machine)
            db.add(machine)
        await db.commit()
        for machine in (good, bad, worse):
            await machine_health.apply_status(db, machine)
        await db.commit()

        fleet = await machine_health.fleet_health(db)
        assert fleet.counts == {"ok": 1, "info": 0, "warning": 1, "critical": 1}
        assert fleet.score == 50
        worst = await machine_health.worst_machines(db)
        assert [m.name for m, _v in worst] == ["worse", "bad"]
        assert await machine_health.fleet_health(db, set()) == machine_health.FleetHealth(
            counts={"ok": 0, "info": 0, "warning": 0, "critical": 0}, unknown=0, score=None
        )


# --- Web ----------------------------------------------------------------------


async def _seed_unhealthy(db_session_factory: Any) -> uuid.UUID:
    async with db_session_factory() as db:
        machine = _machine()
        _stored(machine, WARN)
        machine.health_status = "warning"
        db.add(machine)
        await db.commit()
        return machine.id


async def test_web_panel_snooze_and_clear(client: Any, db_session_factory: Any) -> None:
    machine_id = await _seed_unhealthy(db_session_factory)

    page = await client.get(f"/machines/{machine_id}")
    assert 'id="health-panel"' in page.text
    assert "/ is 90 % full" in page.text
    assert f'action="/machines/{machine_id}/health/snooze"' in page.text
    panel = await client.get(f"/machines/{machine_id}/health-panel")
    assert panel.status_code == 200 and "Storage" in panel.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}

    missing = await client.post(
        f"/machines/{machine_id}/health/snooze", data={**csrf, "key": "cpu.usage"}
    )
    assert missing.status_code == 404
    bad = await client.post(
        f"/machines/{machine_id}/health/snooze",
        data={**csrf, "key": WARN.key, "duration": "forever"},
    )
    assert bad.status_code == 422
    done = await client.post(
        f"/machines/{machine_id}/health/snooze?from=health",
        data={**csrf, "key": WARN.key, "duration": "7d"},
        follow_redirects=False,
    )
    assert done.status_code == 303 and done.headers["location"] == "/health"
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None and machine.health_status == "ok"

    health = await client.get("/health")
    assert health.status_code == 200
    assert f'action="/machines/{machine_id}/health/unsnooze?from=health"' in health.text

    cleared = await client.post(
        f"/machines/{machine_id}/health/unsnooze",
        data={**csrf, "key": WARN.key},
        follow_redirects=False,
    )
    assert cleared.status_code == 303
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None and machine.health_status == "warning"
        actions = (await db.execute(select(AuditLogEntry.action))).scalars().all()
    assert "machine.health.snooze" in actions and "machine.health.snooze.clear" in actions


async def test_web_dashboard_list_filter_and_page(client: Any, db_session_factory: Any) -> None:
    machine_id = await _seed_unhealthy(db_session_factory)
    async with db_session_factory() as db:
        healthy = _machine("healthy")
        healthy.health_status = "ok"
        db.add(healthy)
        await db.commit()

    dashboard = await client.get("/dashboard")
    assert "Fleet health" in dashboard.text and "Health score" in dashboard.text
    listed = await client.get("/machines?status=unhealthy")
    assert f"/machines/{machine_id}" in listed.text and "healthy</a>" not in listed.text
    critical = await client.get("/machines?status=critical")
    assert f"/machines/{machine_id}\"" not in critical.text
    page = await client.get("/health")
    assert "Machines with problems" in page.text and "/ is 90 % full" in page.text


async def test_restricted_account_sees_only_its_machines(
    client: Any, db_session_factory: Any, login_as: Any
) -> None:
    await _seed_unhealthy(db_session_factory)
    from app.db.models.machine_group import MachineGroup
    from app.db.models.role import Permission

    async with db_session_factory() as db:
        group = MachineGroup(name="other")
        db.add(group)
        await db.commit()
        group_id = group.id
    await login_as(client, permissions={Permission.MACHINE_VIEW}, group_ids={group_id})
    page = await client.get("/health")
    assert page.status_code == 200 and "/ is 90 % full" not in page.text


async def test_settings_thresholds_must_be_in_order(client: Any, db_session_factory: Any) -> None:
    await client.get("/settings?tab=checks")
    csrf = {"csrf_token": client.cookies.get("csrftoken")}
    bad = await client.post(
        "/settings/checks",
        data={**csrf, "health_cpu_warn_percent": "96", "health_cpu_critical_percent": "95"},
    )
    assert "must be lower than" in bad.text
    ok = await client.post(
        "/settings/checks",
        data={**csrf, "health_cpu_warn_percent": "70", "health_cpu_critical_percent": "80"},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    async with db_session_factory() as db:
        settings = (await db.execute(select(AppSettings))).scalar_one()
        assert settings.health_cpu_warn_percent == 70


# --- REST API -----------------------------------------------------------------


async def test_api_health(client: Any, db_session_factory: Any) -> None:
    machine_id = await _seed_unhealthy(db_session_factory)
    headers = await _api_token(client)
    base = f"/api/v1/machines/{machine_id}/health"

    body = (await client.get(base, headers=headers)).json()
    assert body["status"] == "warning"
    assert body["categories"]["storage"] == "warning"
    assert body["problems"][0]["key"] == WARN.key
    assert body["problems"][0]["text"] == "/ is 90 % full"
    machine = (await client.get(f"/api/v1/machines/{machine_id}", headers=headers)).json()
    assert machine["health_status"] == "warning"

    missing = await client.post(f"{base}/snoozes", json={"key": "nope"}, headers=headers)
    assert missing.status_code == 404
    too_long = await client.post(
        f"{base}/snoozes", json={"key": WARN.key, "hours": 10**6}, headers=headers
    )
    assert too_long.status_code == 422
    done = await client.post(
        f"{base}/snoozes", json={"key": WARN.key, "hours": 24, "note": "new disk Monday"},
        headers=headers,
    )
    assert done.status_code == 201
    assert done.json()["snooze"]["note"] == "new disk Monday"

    fleet = (await client.get("/api/v1/health", headers=headers)).json()
    assert fleet["counts"]["ok"] == 1 and fleet["score"] == 100
    assert fleet["snoozes"][0]["problem"]["key"] == WARN.key

    cleared = await client.delete(f"{base}/snoozes/{WARN.key}", headers=headers)
    assert cleared.status_code == 204
    again = await client.delete(f"{base}/snoozes/{WARN.key}", headers=headers)
    assert again.status_code == 404


async def test_api_settings_thresholds_must_be_in_order(client: Any) -> None:
    headers = await _api_token(client)
    bad = await client.patch(
        "/api/v1/settings", json={"health_disk_full_warn_days": 1}, headers=headers
    )
    assert bad.status_code == 422 and "must be higher" in bad.text
    ok = await client.patch(
        "/api/v1/settings",
        json={"health_disk_full_warn_days": 10, "health_disk_full_critical_days": 4},
        headers=headers,
    )
    assert ok.status_code == 200
    shown = (await client.get("/api/v1/settings", headers=headers)).json()
    assert shown["health_disk_full_warn_days"] == 10
