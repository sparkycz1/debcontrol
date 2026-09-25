"""Disk-full forecast: the trend math (`app.services.disk_forecast`), the
hourly job that stores it, and the `monitoring.disk_full_days` condition."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

import app.tasks.jobs as jobs
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.services.condition_fields import evaluate_condition
from app.services.disk_forecast import forecast_filesystems, soonest_full_days

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
GB = 1024**3


def _fs(used: int, size: int = 100 * GB, mount: str = "/") -> list[dict[str, object]]:
    return [{"mount": mount, "used_bytes": used, "size_bytes": size, "use_percent": 0}]


def test_growing_disk_forecast():
    # +1 GB/day for 6 days, 60 GB used of 100 at the end → 40 days left.
    samples = [(NOW - timedelta(days=6 - d), _fs((54 + d) * GB)) for d in range(7)]

    forecast = forecast_filesystems(samples, NOW)

    assert forecast["/"]["bytes_per_day"] == GB
    assert forecast["/"]["days_until_full"] == pytest.approx(40.0)


def test_shrinking_or_flat_disk_has_no_estimate():
    samples = [(NOW - timedelta(hours=10 - h), _fs((50 - h) * GB)) for h in range(10)]

    assert forecast_filesystems(samples, NOW)["/"]["days_until_full"] is None


def test_full_disk_is_zero_days():
    samples = [(NOW - timedelta(hours=10 - h), _fs(100 * GB)) for h in range(10)]

    assert forecast_filesystems(samples, NOW)["/"]["days_until_full"] == 0.0


def test_too_little_history_is_skipped():
    few = [(NOW - timedelta(hours=h), _fs(50 * GB)) for h in range(3)]
    short = [(NOW - timedelta(minutes=10 * m), _fs(50 * GB)) for m in range(10)]

    assert forecast_filesystems(few, NOW) == {}
    assert forecast_filesystems(short, NOW) == {}


def test_soonest_full_days_picks_the_minimum():
    assert soonest_full_days(
        {"/": {"days_until_full": 40.0}, "/srv": {"days_until_full": 5.5}, "/x": {}}
    ) == 5.5
    assert soonest_full_days(None) is None


def test_condition_field_reads_the_stored_forecast():
    machine = Machine(
        name="m", ip_address="10.0.0.1", port=22, username="u", auth_method=AuthMethod.PASSWORD
    )
    machine.disk_forecast = {"/": {"days_until_full": 5.5}}

    assert evaluate_condition("monitoring.disk_full_days", "lt", "7", machine, None, None)
    machine.disk_forecast = {"/": {"days_until_full": None}}
    assert not evaluate_condition("monitoring.disk_full_days", "lt", "7", machine, None, None)


async def test_job_stores_the_forecast(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as session:
        machine = Machine(
            name="fc", ip_address="10.0.0.2", port=22, username="u",
            auth_method=AuthMethod.PASSWORD,
        )
        session.add(machine)
        await session.flush()
        for d in range(7):
            session.add(
                MachineMonitoringSample(
                    machine_id=machine.id,
                    sampled_at=now - timedelta(days=6 - d),
                    filesystems=_fs((54 + d) * GB),
                )
            )
        await session.commit()
        machine_id = machine.id

    result = await jobs._forecast_machine_disks(str(machine_id))

    assert result == {"ok": True, "mounts": 1}
    async with db_session_factory() as session:
        stored = await session.get(Machine, machine_id)
        assert stored is not None
        assert stored.disk_forecast is not None
        assert stored.disk_forecast["/"]["days_until_full"] == pytest.approx(40.0, abs=0.5)


async def test_job_handles_unknown_machine(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    assert (await jobs._forecast_machine_disks(str(uuid.uuid4())))["ok"] is False
