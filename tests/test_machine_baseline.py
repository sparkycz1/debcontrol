"""Usual behavior of each machine (`app.services.machine_baseline`): what it
learns, what counts as unusual, how health uses it (unusual findings, a
usual high reading muted to information), the nightly task, the settings,
the API and the Dashboard widgets (`app.services.dashboard_widgets`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.app_settings import AppSettings
from app.db.models.machine import Machine
from app.db.models.machine_baseline import MachineBaseline
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.user import User
from app.services import dashboard_layout, dashboard_widgets, machine_baseline, machine_health
from app.services.machine_baseline import Baseline, Bucket, Reading
from app.services.machine_health import Thresholds
from app.tasks import baselines as baseline_tasks
from tests.test_api_v1_extended import _api_token
from tests.test_machine_health import _keys, _machine

# A Wednesday, 02:30 UTC.
NOW = datetime(2026, 11, 25, 2, 30, tzinfo=UTC)
HOUR = machine_baseline.hour_of_week(NOW)


def _sample(minutes_ago: float = 0, at: datetime = NOW, **kwargs: Any) -> MachineMonitoringSample:
    return MachineMonitoringSample(
        machine_id=kwargs.pop("machine_id", None) or uuid.uuid4(),
        sampled_at=at - timedelta(minutes=minutes_ago),
        **kwargs,
    )


def _baseline(
    since_days: int = 30, **per_metric: Bucket
) -> Baseline:
    buckets: dict[str, list[Bucket | None]] = {}
    for metric, bucket in per_metric.items():
        row: list[Bucket | None] = [None] * machine_baseline.HOURS
        row[HOUR] = bucket
        buckets[metric] = row
    return Baseline(
        since=NOW - timedelta(days=since_days), computed_at=NOW, sample_count=1000,
        buckets=buckets,
    )


# A backup server: 92 % CPU every night at this hour, rarely more.
BUSY_NIGHT = Bucket(samples=200, median=90.0, spread=2.0, p5=85.0, p95=94.0)
# An idle machine at this hour.
IDLE = Bucket(samples=200, median=4.0, spread=1.0, p5=2.0, p95=8.0)


# --- Learning -----------------------------------------------------------------


def test_hour_of_week_and_bucket_statistics() -> None:
    assert machine_baseline.hour_of_week(datetime(2026, 11, 23, 0, 5, tzinfo=UTC)) == 0  # Monday
    assert machine_baseline.hour_of_week(datetime(2026, 11, 29, 23, 59, tzinfo=UTC)) == 167
    bucket = machine_baseline.bucket_of([1, 2, 3, 4, 100])
    assert bucket is not None
    # The median and its spread barely notice the one outlier.
    assert bucket.median == 3 and round(bucket.spread, 2) == 1.48
    assert bucket.p5 < 2 and bucket.p95 > 4
    assert machine_baseline.bucket_of([]) is None


def test_compute_takes_the_neighbouring_hours_and_network_rates() -> None:
    start = datetime(2026, 11, 2, 2, 0, tzinfo=UTC)  # a Monday 02:00
    readings = [
        Reading(start + timedelta(minutes=10 * i), cpu=50.0 + i, memory=40.0, load=1.0,
                network_io=[{"iface": "eth0", "rx_bytes": 1000 * i, "tx_bytes": 0},
                            {"iface": "veth1", "rx_bytes": 10**9 * i, "tx_bytes": 0}],
                latency=None)
        for i in range(6)
    ]
    buckets, count = machine_baseline.compute(readings)

    assert count == 6
    monday_two = machine_baseline.hour_of_week(start)
    cpu = buckets["cpu"]
    # 02:00 itself, and 01:00 and 03:00 through their neighbour.
    for hour in (monday_two - 1, monday_two, monday_two + 1):
        bucket = cpu[hour]
        assert bucket is not None and bucket.samples == 6
    assert cpu[monday_two + 2] is None
    network = buckets["network"][monday_two]
    # 1000 bytes per 600 s on eth0; the veth is left out.
    assert network is not None and network.samples == 5
    assert round(network.median, 2) == round(1000 / 600, 2)
    assert buckets["latency"][monday_two] is None


def test_network_rate_skips_gaps_and_reboots() -> None:
    at = NOW
    io = [{"iface": "eth0", "rx_bytes": 5000, "tx_bytes": 5000}]
    before = [{"iface": "eth0", "rx_bytes": 2000, "tx_bytes": 2000}]
    assert machine_baseline.network_rate(at, io, at - timedelta(seconds=60), before) == 100
    assert machine_baseline.network_rate(at, io, at - timedelta(hours=1), before) is None
    assert machine_baseline.network_rate(at, before, at - timedelta(seconds=60), io) is None
    assert machine_baseline.network_rate(at, io, at - timedelta(seconds=60), []) is None


# --- Comparing ------------------------------------------------------------------


def test_what_counts_as_unusual() -> None:
    # Idle at 4 %: 40 % is unusual, 70 % far off, 12 % just noise.
    assert machine_baseline.unusual("cpu", 40, IDLE) == "high"
    assert machine_baseline.unusual("cpu", 70, IDLE) == "very_high"
    assert machine_baseline.unusual("cpu", 12, IDLE) is None
    # A busy server: 95 % at its busy hour is not unusual.
    assert machine_baseline.unusual("cpu", 95, BUSY_NIGHT) is None
    assert machine_baseline.is_usual(93, BUSY_NIGHT)
    assert not machine_baseline.is_usual(99, BUSY_NIGHT)
    # Traffic that collapses on a busy link.
    busy_link = Bucket(samples=100, median=50e6, spread=5e6, p5=30e6, p95=70e6)
    assert machine_baseline.unusual("network", 1e6, busy_link) == "low"
    assert machine_baseline.unusual("network", 40e6, busy_link) is None
    # A higher sensitivity number is less sensitive.
    assert machine_baseline.unusual("cpu", 40, IDLE, deviations=10) is None


def test_health_mutes_a_usual_high_reading_and_reports_unusual_ones() -> None:
    machine = _machine()
    busy = [_sample(i, cpu_percent=92, ram_used_bytes=50, ram_total_bytes=100) for i in range(3)]
    th = Thresholds()

    plain = machine_health.evaluate(machine, busy, th, now=NOW)
    usual = machine_health.evaluate(machine, busy, th, now=NOW, baseline=_baseline(cpu=BUSY_NIGHT))
    off = machine_health.evaluate(
        machine, busy, Thresholds(mute_usual=False), now=NOW, baseline=_baseline(cpu=BUSY_NIGHT)
    )
    learning = machine_health.evaluate(
        machine, busy, th, now=NOW, baseline=_baseline(since_days=5, cpu=BUSY_NIGHT)
    )

    assert _keys(plain) == {"cpu.usage": "warning"}
    muted = next(f for f in usual if f.key == "cpu.usage")
    assert muted.severity == "info" and muted.message == "cpu_high_usual"
    assert muted.params == {"percent": 92, "usual": 94}
    assert _keys(off) == {"cpu.usage": "warning"}
    # Not two weeks of history yet: thresholds as always.
    assert _keys(learning) == {"cpu.usage": "warning"}

    # Critical always counts.
    critical = [_sample(i, cpu_percent=97) for i in range(3)]
    flat = Bucket(samples=200, median=96.0, spread=1.0, p5=94.0, p95=99.0)
    assert _keys(machine_health.evaluate(
        machine, critical, th, now=NOW, baseline=_baseline(cpu=flat)
    )) == {"cpu.usage": "critical"}

    # Idle at this hour, now at 60 %: under the threshold, but unusual.
    odd = [_sample(i, cpu_percent=60, load1=6.0) for i in range(3)]
    found = machine_health.evaluate(
        machine, odd, th, now=NOW,
        baseline=_baseline(cpu=IDLE, load=Bucket(200, 0.3, 0.1, 0.1, 0.6)),
    )
    assert _keys(found) == {"cpu.unusual": "warning", "cpu.load_unusual": "warning"}
    text = machine_health.finding_text(next(f for f in found if f.key == "cpu.unusual"), "en")
    assert text == "Unusual CPU use: 60 %, usually 4 % at this hour"
    assert "cpu.unusual" in machine_health.UNUSUAL_KEYS

    # Switched off: nothing about usual behavior at all.
    assert machine_health.evaluate(
        machine, odd, Thresholds(anomaly_detection=False), now=NOW, baseline=_baseline(cpu=IDLE)
    ) == []


def test_a_threshold_finding_is_not_repeated_as_unusual() -> None:
    samples = [_sample(i, cpu_percent=88) for i in range(3)]
    found = machine_health.evaluate(
        _machine(), samples, Thresholds(mute_usual=False), now=NOW, baseline=_baseline(cpu=IDLE)
    )
    assert _keys(found) == {"cpu.usage": "warning"}


def test_ranges_now() -> None:
    samples = [_sample(i, cpu_percent=60) for i in range(3)]
    ranges = machine_baseline.ranges_now(_baseline(cpu=IDLE, memory=IDLE), samples, NOW)
    by_metric = {r.metric: r for r in ranges}
    assert by_metric["cpu"].verdict == "very_high" and by_metric["cpu"].value == 60
    assert by_metric["memory"].value is None and by_metric["memory"].verdict is None
    assert machine_baseline.ranges_now(None, samples, NOW) == []


# --- Stored, the task, settings, API ------------------------------------------------


async def _machine_with_history(db_session_factory: Any, *, days: int = 16) -> uuid.UUID:
    """Every 30 minutes for `days` days: 5 % CPU, but 90 % at 02:00-02:59."""
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    async with db_session_factory() as db:
        machine = _machine()
        db.add(machine)
        await db.commit()
        rows = []
        for step in range(days * 48):
            at = now - timedelta(minutes=30 * step)
            rows.append(
                MachineMonitoringSample(
                    machine_id=machine.id, sampled_at=at,
                    cpu_percent=90.0 if at.hour == 2 else 5.0,
                    ram_used_bytes=40, ram_total_bytes=100,
                    load1=0.2, internet_latency_ms=12.0,
                )
            )
        db.add_all(rows)
        await db.commit()
        return machine.id


async def test_recompute_stores_and_the_task_queues_each_machine(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_id = await _machine_with_history(db_session_factory)
    async with db_session_factory() as db:
        db.add(_machine("empty"))
        await db.commit()

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    queued: list[str] = []
    monkeypatch.setattr(baseline_tasks.learn_machine_baseline, "delay", queued.append)
    assert await baseline_tasks._learn_all_baselines() == 2
    assert str(machine_id) in queued

    assert await baseline_tasks._learn_machine_baseline(str(machine_id)) is True
    async with db_session_factory() as db:
        empty = (await db.execute(select(Machine).where(Machine.name == "empty"))).scalar_one()
    assert await baseline_tasks._learn_machine_baseline(str(empty.id)) is False

    async with db_session_factory() as db:
        stored = await db.get(MachineBaseline, machine_id)
        assert stored is not None and stored.sample_count == 16 * 48
        baseline = await machine_baseline.load(db, machine_id)
    assert baseline is not None
    at_two = datetime.now(UTC).replace(hour=2, minute=30)
    at_noon = at_two.replace(hour=12)
    assert baseline.ready(datetime.now(UTC))
    two = baseline.usual("cpu", at_two)
    noon = baseline.usual("cpu", at_noon)
    assert two is not None and two.p95 == 90
    assert noon is not None and noon.median == 5


async def test_settings_page_and_api(client: Any, db_session_factory: Any) -> None:
    page = await client.get("/settings?tab=checks")
    assert 'name="health_anomaly_deviations"' in page.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}
    saved = await client.post(
        "/settings/checks",
        data={**csrf, "health_anomaly_deviations": "6",
              "health_anomaly_detection_present": "1", "health_anomaly_detection": "1",
              "health_anomaly_mute_usual_present": "1"},
        follow_redirects=False,
    )
    assert saved.status_code == 303
    async with db_session_factory() as db:
        settings = (await db.execute(select(AppSettings))).scalar_one()
        assert settings.health_anomaly_deviations == 6
        assert settings.health_anomaly_detection and not settings.health_anomaly_mute_usual
        assert Thresholds.from_settings(settings).anomaly_deviations == 6

    headers = await _api_token(client)
    bad = await client.patch(
        "/api/v1/settings", json={"health_anomaly_deviations": 1}, headers=headers
    )
    ok = await client.patch(
        "/api/v1/settings",
        json={"health_anomaly_mute_usual": True, "health_anomaly_deviations": 3},
        headers=headers,
    )
    shown = (await client.get("/api/v1/settings", headers=headers)).json()
    assert bad.status_code == 422
    assert ok.status_code == 200
    assert shown["health_anomaly_mute_usual"] is True and shown["health_anomaly_deviations"] == 3


async def test_usual_behavior_on_the_panel_and_in_the_api(
    client: Any, db_session_factory: Any
) -> None:
    machine_id = await _machine_with_history(db_session_factory)
    async with db_session_factory() as db:
        await machine_baseline.recompute(db, machine_id)
        await db.commit()

    panel = await client.get(f"/machines/{machine_id}/health-panel")
    headers = await _api_token(client)
    body = (await client.get(f"/api/v1/machines/{machine_id}/health/usual", headers=headers)).json()
    week = (
        await client.get(f"/api/v1/machines/{machine_id}/health/usual?week=true", headers=headers)
    ).json()

    assert 'id="usual-behavior"' in panel.text and "Usual range" in panel.text
    assert body["enabled"] and body["learned"] and body["ready"]
    assert {r["metric"] for r in body["ranges"]} >= {"cpu", "memory", "load", "latency"}
    assert "week" not in body
    assert len(week["week"]["cpu"]) == machine_baseline.HOURS


async def test_a_machine_still_learning(client: Any, db_session_factory: Any) -> None:
    machine_id = await _machine_with_history(db_session_factory, days=3)
    async with db_session_factory() as db:
        await machine_baseline.recompute(db, machine_id)
        await db.commit()
    panel = await client.get(f"/machines/{machine_id}/health-panel")
    headers = await _api_token(client)
    body = (await client.get(f"/api/v1/machines/{machine_id}/health/usual", headers=headers)).json()
    assert "Still learning" in panel.text
    assert body["learned"] and not body["ready"] and body["ranges"] == []


# --- Dashboard widgets ------------------------------------------------------------


async def _fleet(db_session_factory: Any) -> uuid.UUID:
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        busy = _machine("busy")
        calm = _machine("calm")
        calm.ip_address = "10.0.0.2"
        odd = _machine("odd")
        odd.health = {
            "at": now.isoformat(),
            "findings": [machine_health.Finding(
                "cpu.unusual", "cpu", "warning", "cpu_unusual", {"value": 60, "usual": 4},
                "monitoring",
            ).as_dict()],
        }
        odd.health_status = "warning"
        calm.docker_status = "ok"
        calm.docker_containers = [
            {"name": "grafana", "state": "running", "compose_project": "monitoring",
             "ports": "0.0.0.0:3000->3000/tcp"},
            {"name": "stopped", "state": "exited", "ports": "0.0.0.0:8080->80/tcp"},
        ]
        db.add_all([busy, calm, odd])
        await db.commit()
        db.add_all([
            MachineMonitoringSample(machine_id=busy.id, sampled_at=now, cpu_percent=95,
                                    ram_used_bytes=30, ram_total_bytes=100,
                                    internet_latency_ms=180, internet_loss_percent=5),
            MachineMonitoringSample(machine_id=calm.id, sampled_at=now, cpu_percent=3,
                                    ram_used_bytes=80, ram_total_bytes=100,
                                    internet_latency_ms=10, gateway_latency_ms=0.4),
            # Too old to be "now".
            MachineMonitoringSample(machine_id=odd.id, sampled_at=now - timedelta(hours=2),
                                    cpu_percent=99),
        ])
        await db.commit()
        return odd.id


async def test_widgets_data(db_session_factory: Any) -> None:
    odd_id = await _fleet(db_session_factory)
    async with db_session_factory() as db:
        unusual = await dashboard_widgets.unusual_machines(db)
        readings = await dashboard_widgets.latest_readings(db)
        links, total = await dashboard_widgets.app_links(db)
        nobody = await dashboard_widgets.latest_readings(db, set())

    assert [(m.id, [f.key for f in fs]) for m, fs in unusual] == [(odd_id, ["cpu.unusual"])]
    top = dashboard_widgets.top_machines(readings)
    assert [r.name for r in top.cpu] == ["busy", "calm"]
    assert [r.name for r in top.memory] == ["calm", "busy"]
    latency = dashboard_widgets.latency(readings)
    assert [r.name for r in latency.worst] == ["busy", "calm"] and latency.average_ms == 95
    assert total == 1 and links[0].url == "http://10.0.0.2:3000" and links[0].stack == "monitoring"
    assert nobody == []


async def test_widgets_on_the_dashboard_and_in_the_api(
    client: Any, db_session_factory: Any
) -> None:
    await _fleet(db_session_factory)
    before = await client.get("/dashboard")
    assert "Busiest machines" in before.text  # offered for arranging...
    assert "Web interfaces</h2>" not in before.text  # ...but not shown

    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None
        layout = dashboard_layout.DEFAULT
        for key in dashboard_layout.OPTIONAL:
            layout = dashboard_layout.set_hidden(layout, key, hidden=False)
        user.dashboard_layout = dashboard_layout.to_store(layout)
        await db.commit()

    page = await client.get("/dashboard")
    headers = await _api_token(client)
    api = (await client.get("/api/v1/dashboard/widgets", headers=headers)).json()

    for heading in ("Unusual behavior", "Busiest machines", "Internet latency", "Web interfaces"):
        assert f"{heading}</h2>" in page.text
    assert "Unusual CPU use: 60 %" in page.text
    assert 'href="http://10.0.0.2:3000" target="_blank" rel="noopener noreferrer"' in page.text
    assert api["unusual"][0]["problems"][0]["text"].startswith("Unusual CPU use")
    assert api["top_machines"]["cpu"][0]["name"] == "busy"
    assert api["latency"]["measured"] == 2 and api["links_total"] == 1
