"""`MachineMonitoringSample` downsampling — see app/db/models/app_settings.py's
docstring on `monitoring_downsample_after_days`/`_interval_minutes` for why
this exists (a chart already buckets old samples for display, so keeping
every raw one forever costs storage for resolution nothing renders). Same
shape as the monitoring-retention tests — this thins instead of deletes.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.app_settings import get_or_create_app_settings
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample

# The async implementation behind the Celery task of the same (unprefixed)
# name — the task itself is a thin `asyncio.run(...)` wrapper.
from app.tasks.jobs import _downsample_old_monitoring_samples


async def _make_sample(db: AsyncSession, machine_id: uuid.UUID, *, sampled_at: datetime) -> None:
    db.add(MachineMonitoringSample(machine_id=machine_id, sampled_at=sampled_at, cpu_percent=1.0))


async def test_downsample_keeps_one_sample_per_bucket_for_old_data(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.monitoring_downsample_after_days = 7
        app_settings.monitoring_downsample_interval_minutes = 60

        machine = Machine(
            name="m1", ip_address="10.1.1.1", username="admin", auth_method=AuthMethod.SSH_KEY
        )
        db.add(machine)
        await db.flush()

        # Three samples inside the same hour-wide bucket, ten days ago
        # (older than after_days=7) — only the first should survive.
        base = datetime.now(UTC) - timedelta(days=10)
        await _make_sample(db, machine.id, sampled_at=base)
        await _make_sample(db, machine.id, sampled_at=base + timedelta(minutes=15))
        await _make_sample(db, machine.id, sampled_at=base + timedelta(minutes=45))
        # A recent sample (inside after_days) must never be touched.
        recent_at = datetime.now(UTC) - timedelta(hours=1)
        await _make_sample(db, machine.id, sampled_at=recent_at)
        await db.commit()

    await _downsample_old_monitoring_samples()

    async with db_session_factory() as db:
        result = await db.execute(
            select(MachineMonitoringSample).order_by(MachineMonitoringSample.sampled_at)
        )
        remaining = list(result.scalars().all())
        assert len(remaining) == 2
        assert remaining[0].sampled_at.replace(tzinfo=UTC) - base < timedelta(seconds=5)
        assert remaining[1].sampled_at.replace(tzinfo=UTC) - recent_at < timedelta(seconds=5)


async def test_downsample_skipped_when_disabled(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.monitoring_downsample_after_days = None

        machine = Machine(
            name="m1", ip_address="10.1.1.1", username="admin", auth_method=AuthMethod.SSH_KEY
        )
        db.add(machine)
        await db.flush()

        base = datetime.now(UTC) - timedelta(days=9999)
        await _make_sample(db, machine.id, sampled_at=base)
        await _make_sample(db, machine.id, sampled_at=base + timedelta(minutes=1))
        await db.commit()

    await _downsample_old_monitoring_samples()

    async with db_session_factory() as db:
        result = await db.execute(select(MachineMonitoringSample))
        assert len(list(result.scalars().all())) == 2


async def test_downsampling_settings_persist(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/settings/monitoring-downsampling",
        data={"after_days": "14", "interval_minutes": "30", "csrf_token": csrf_token},
    )
    assert response.status_code == 303

    page = await client.get("/settings?tab=checks")
    assert 'value="14"' in page.text
    assert 'value="30"' in page.text
