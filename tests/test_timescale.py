"""TimescaleDB support (app/db/timescale.py): off on anything without the
extension, compression ages, whole-day chunk drops in the retention purge,
the status page reading the daily aggregates, and the Settings page/API
showing it. The SQL against a real TimescaleDB is exercised by the Docker
smoke test (wiki/Development), not here."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import inspect, select, text

import app.tasks.jobs as jobs
from app.core.app_settings import get_or_create_app_settings
from app.db import timescale
from app.db.base import Base
from app.db.models.audit_log import AuditLogEntry
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_reachability_sample import MachineReachabilitySample
from app.services import status_page
from tests.test_update_history import _api_token


@pytest.mark.parametrize(
    ("table", "downsample", "expected"),
    [
        (timescale.MONITORING, None, 7),
        (timescale.MONITORING, 3, 7),
        (timescale.MONITORING, 7, 8),
        (timescale.MONITORING, 30, 31),
        (timescale.REACHABILITY, 30, 7),
        (timescale.ENDPOINT_RESULTS, 7, 7),
    ],
)
def test_compress_after_days(
    table: timescale.Hypertable, downsample: int | None, expected: int
) -> None:
    assert timescale.compress_after_days(table, downsample) == expected


def test_time_column_is_part_of_every_history_primary_key():
    models: list[tuple[type[Base], str]] = [
        (MachineMonitoringSample, "sampled_at"),
        (MachineReachabilitySample, "checked_at"),
        (EndpointCheckResult, "checked_at"),
    ]
    for model, time_column in models:
        assert [c.name for c in inspect(model).primary_key] == ["id", time_column]


async def test_everything_is_a_no_op_without_timescaledb(db_session_factory, monkeypatch):
    monkeypatch.setattr(timescale, "_enabled", None)
    async with db_session_factory() as session:
        assert await timescale.enabled(session) is False
        assert await timescale.describe(session) is None
        await timescale.apply_policies(session, 7)
        await timescale.refresh_aggregates(session)


async def _machine(session: Any, name: str, retention: int | None) -> Machine:
    machine = Machine(
        name=name,
        ip_address="10.0.0.1",
        port=22,
        username="root",
        auth_method=AuthMethod.PASSWORD,
        monitoring_history_retention_days=retention,
    )
    session.add(machine)
    await session.flush()
    return machine


@pytest.mark.parametrize(
    ("default", "overrides", "machine_days", "endpoint_days"),
    [
        (30, [None, 10], 30, 30),  # longest wins; shorter goes row by row
        (30, [60, None], 60, 30),
        (None, [10, None], None, None),  # one machine keeps forever
        (None, [10, 20], 20, None),
    ],
)
async def test_purge_drops_whole_days_only_where_every_machine_allows(
    db_session_factory, monkeypatch, default, overrides, machine_days, endpoint_days
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    monkeypatch.setattr(timescale, "_enabled", True)
    calls: list[tuple[str, datetime]] = []

    async def fake_drop(session: Any, relation: str, older_than: datetime) -> int:
        calls.append((relation, older_than))
        return 2

    monkeypatch.setattr(timescale, "drop_old_chunks", fake_drop)
    async with db_session_factory() as session:
        for index, days in enumerate(overrides):
            await _machine(session, f"m{index}", days)
        app_settings = await get_or_create_app_settings(session)
        app_settings.monitoring_history_retention_days = default
        await session.commit()

    before = datetime.now(UTC)
    await jobs._purge_old_monitoring_samples()

    by_relation = dict(calls)
    for relation, days in (
        (timescale.MONITORING.table, machine_days),
        (timescale.REACHABILITY.table, machine_days),
        (timescale.REACHABILITY_DAILY, machine_days),
        (timescale.ENDPOINT_RESULTS.table, endpoint_days),
        (timescale.ENDPOINT_CHECK_DAILY, endpoint_days),
    ):
        if days is None:
            assert relation not in by_relation
        else:
            expected = before - timedelta(days=days)
            assert abs((by_relation[relation] - expected).total_seconds()) < 60

    async with db_session_factory() as session:
        audit = (
            await session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "monitoring_samples.purge")
            )
        ).scalar_one_or_none()
    if calls:
        assert audit is not None
        assert audit.details["chunks_dropped"] == 2 * len(calls)
        assert "whole day chunk" in audit.summary
    else:
        assert audit is None


async def test_downsampling_skips_compressed_days_on_timescaledb(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    monkeypatch.setattr(timescale, "_enabled", True)
    applied: list[int | None] = []

    async def fake_apply(session: Any, after_days: int | None) -> None:
        applied.append(after_days)

    monkeypatch.setattr(timescale, "apply_policies", fake_apply)
    now = datetime.now(UTC)
    async with db_session_factory() as session:
        machine = await _machine(session, "web", None)
        # Two samples a minute apart at 7.5 days (thinned; compression waits
        # until 8) and at 20 days (compressed long ago: left alone).
        for days in (7.5, 20):
            for minute in (0, 1):
                session.add(
                    MachineMonitoringSample(
                        machine_id=machine.id,
                        sampled_at=now - timedelta(days=days, minutes=minute),
                    )
                )
        app_settings = await get_or_create_app_settings(session)
        app_settings.monitoring_downsample_after_days = 7
        app_settings.monitoring_downsample_interval_minutes = 60
        await session.commit()

    await jobs._downsample_old_monitoring_samples()

    assert applied == [7]
    async with db_session_factory() as session:
        left = (await session.execute(select(MachineMonitoringSample.sampled_at))).scalars().all()
    ages = sorted(int((now - at.replace(tzinfo=UTC)).total_seconds() // 86400) for at in left)
    assert ages == [7, 20, 20]


async def test_status_page_reads_daily_aggregates(db_session_factory, monkeypatch):
    monkeypatch.setattr(timescale, "_enabled", True)
    today = datetime.now(UTC).date()
    async with db_session_factory() as session:
        machine = await _machine(session, "web", None)
        machine.is_reachable = True
        # Stand-in for the continuous aggregate (a plain table on SQLite).
        await session.execute(
            text(
                "CREATE TABLE reachability_daily "
                "(machine_id CHAR(32), day DATETIME, up INT, total INT)"
            )
        )
        for offset, up, total in ((0, 10, 10), (1, 5, 10), (40, 0, 10)):
            day = datetime(today.year, today.month, today.day, tzinfo=UTC) - timedelta(days=offset)
            await session.execute(
                text("INSERT INTO reachability_daily VALUES (:m, :d, :u, :t)"),
                {"m": machine.id.hex, "d": day.replace(tzinfo=None), "u": up, "t": total},
            )
        app_settings = await get_or_create_app_settings(session)
        app_settings.status_page_machine_ids = [str(machine.id)]
        app_settings.status_page_show_history = True
        await session.commit()

        result = await status_page.build(session, app_settings)

    (item,) = result.items
    assert item.uptime_percent == 75.0  # 15 of 20; the 40-day-old row is outside
    assert item.days[-1].uptime_percent == 100.0
    assert item.days[-2].uptime_percent == 50.0
    assert item.days[0].uptime_percent is None


async def test_settings_page_and_api_show_timescaledb(client, monkeypatch):
    info = {
        "version": "2.31.0",
        "compress_after_days": {
            "machine_monitoring_samples": 8,
            "machine_reachability_samples": 7,
            "endpoint_check_results": 7,
        },
    }

    async def fake_describe(session: Any) -> dict[str, Any]:
        return info

    page = await client.get("/settings?tab=checks")
    assert "TimescaleDB" not in page.text

    monkeypatch.setattr(timescale, "describe", fake_describe)
    page = await client.get("/settings?tab=checks")
    assert "TimescaleDB 2.31.0" in page.text
    assert "after 8 days" in page.text

    headers = await _api_token(client)
    response = await client.get("/api/v1/settings", headers=headers)
    assert response.json()["timescaledb"] == info
