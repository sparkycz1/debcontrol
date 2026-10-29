"""Retention purges delete in batches (one transaction each), and the
time-series tables get time-ordered UUIDv7 primary keys."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import app.tasks.jobs as jobs
from app.core.app_settings import get_or_create_app_settings
from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample


async def test_purge_deletes_everything_in_batches(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    monkeypatch.setattr(jobs, "_DELETE_BATCH_SIZE", 3)
    now = datetime.now(UTC)
    async with db_session_factory() as session:
        machine = Machine(
            name="web1", ip_address="10.0.0.1", port=22, username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        session.add(machine)
        await session.flush()
        for days in range(1, 21):  # 20 rows, days 10-20 past a 10-day retention
            session.add(
                MachineMonitoringSample(
                    machine_id=machine.id, sampled_at=now - timedelta(days=days, hours=1)
                )
            )
        app_settings = await get_or_create_app_settings(session)
        app_settings.monitoring_history_retention_days = 10
        await session.commit()

    commits = 0
    real_commit = AsyncSession.commit

    async def counting_commit(self: AsyncSession) -> None:
        nonlocal commits
        commits += 1
        await real_commit(self)

    monkeypatch.setattr(AsyncSession, "commit", counting_commit)
    await jobs._purge_old_monitoring_samples()

    async with db_session_factory() as session:
        left = (
            await session.execute(select(func.count()).select_from(MachineMonitoringSample))
        ).scalar_one()
        audit = (
            await session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "monitoring_samples.purge")
            )
        ).scalar_one()
    assert left == 9
    assert audit.details == {"deleted_count": 11}
    assert commits >= 4  # 11 rows in batches of 3, plus the audit entry


async def test_time_series_rows_get_uuid7_ids(db_session_factory):
    async with db_session_factory() as session:
        machine = Machine(
            name="web2", ip_address="10.0.0.2", port=22, username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        session.add(machine)
        await session.flush()
        sample = MachineMonitoringSample(machine_id=machine.id, sampled_at=datetime.now(UTC))
        session.add(sample)
        await session.commit()
        assert sample.id.version == 7
        assert machine.id.version == 4
