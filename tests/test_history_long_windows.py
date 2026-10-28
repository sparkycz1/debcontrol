"""A window holding more rows than `MAX_RAW_SAMPLES` is thinned evenly
across the whole range, never cut short: a 30/90-day view used to show
only its oldest ~28 days (oldest-first LIMIT)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_reachability_sample import MachineReachabilitySample
from app.services import monitoring_history
from app.services.endpoint_check_history import load_check_history
from app.services.monitoring_history import load_machine_history

ROWS = 95
CAP = 10


@pytest.fixture(autouse=True)
def _small_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(monitoring_history, "MAX_RAW_SAMPLES", CAP)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def _seed_machine(db_session_factory: Any, now: datetime) -> uuid.UUID:
    async with db_session_factory() as session:
        machine = Machine(
            name="web1", ip_address="10.0.0.1", port=22, username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        session.add(machine)
        await session.flush()
        for i in range(ROWS):
            # one row per day, the newest an hour ago
            at = now - timedelta(days=ROWS - 1 - i, hours=1)
            session.add(
                MachineMonitoringSample(
                    machine_id=machine.id, sampled_at=at, cpu_percent=float(i),
                    network_io=[{"iface": "eth0", "rx_bytes": i * 86400, "tx_bytes": 0}],
                )
            )
            session.add(
                MachineReachabilitySample(
                    machine_id=machine.id, checked_at=at, reachable=i != ROWS - 1,
                    latency_ms=float(i),
                )
            )
        await session.commit()
        return machine.id


async def test_machine_history_spans_the_whole_window(db_session_factory):
    now = datetime.now(UTC)
    machine_id = await _seed_machine(db_session_factory, now)
    async with db_session_factory() as session:
        history, availability = await load_machine_history(session, machine_id, "90d")

    # 90 days back from now: rows 5..94 (days 89..0 ago) are inside.
    assert history.sample_count == 90
    assert availability.sample_count == 90
    assert history.truncated is False and availability.truncated is False
    stamps = [_as_utc(ts) for ts in history.bucket_timestamps]
    assert len(stamps) <= CAP + 1
    assert now - stamps[0] > timedelta(days=85)
    # the newest sample is always kept, so the latest reading is current
    assert now - stamps[-1] < timedelta(hours=2)
    assert availability.latest_reachable is False
    assert availability.latest_latency_ms == float(ROWS - 1)
    # rates from thinned cumulative counters are still per second
    rates = [v for v in history.network_rx_by_iface["eth0"] if v is not None]
    assert rates and all(v == pytest.approx(1.0) for v in rates)


async def test_short_window_returns_every_row(db_session_factory):
    now = datetime.now(UTC)
    machine_id = await _seed_machine(db_session_factory, now)
    async with db_session_factory() as session:
        history, availability = await load_machine_history(session, machine_id, "7d")
    assert history.sample_count == availability.sample_count == 7
    assert len(history.bucket_timestamps) == 7


async def test_check_history_counts_every_result_when_thinned(db_session_factory):
    now = datetime.now(UTC)
    async with db_session_factory() as session:
        check = EndpointCheck(name="api", kind="http", target="https://svc.test/health")
        session.add(check)
        await session.flush()
        for i in range(ROWS):
            ok = i % 7 != 3  # failures the thinning would mostly skip
            session.add(
                EndpointCheckResult(
                    check_id=check.id, checked_at=now - timedelta(days=ROWS - 1 - i, hours=1),
                    ok=ok, status_code=200 if ok else 503, latency_ms=100.0,
                    error=None if ok else f"fail {i}",
                )
            )
        await session.commit()
        check_id = check.id

    async with db_session_factory() as session:
        history = await load_check_history(session, check_id, "90d")

    inside = range(ROWS - 90, ROWS)
    failures = [i for i in inside if i % 7 == 3]
    assert history.sample_count == 90
    assert history.failure_count == len(failures)
    assert history.uptime_percent == round((90 - len(failures)) / 90 * 100, 2)
    assert history.avg_latency_ms == 100.0
    assert [f.error for f in history.recent_failures][:2] == [
        f"fail {failures[-1]}", f"fail {failures[-2]}"
    ]
    assert len(history.bucket_timestamps) <= CAP + 1
    assert now - _as_utc(history.bucket_timestamps[-1]) < timedelta(hours=2)
