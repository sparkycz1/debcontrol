"""`NotificationLog` retention/purge — see app/db/models/app_settings.py's
docstring on `notification_log_retention_days` for why this exists. Same
shape as the update-run retention tests (tests/test_update_run_retention.py).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.app_settings import get_or_create_app_settings
from app.db.models.notification_log import NotificationLog

# The async implementation behind the Celery task of the same (unprefixed)
# name — the task itself is a thin `asyncio.run(...)` wrapper.
from app.tasks.jobs import _purge_old_notification_logs


async def _make_log(db: AsyncSession, *, sent_at: datetime) -> None:
    db.add(
        NotificationLog(
            rule_name="test rule",
            event_type="machine.unreachable",
            channel="email",
            target="someone@example.com",
            status="sent",
            sent_at=sent_at,
        )
    )


async def test_purge_old_notification_logs_respects_retention(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.notification_log_retention_days = 30

        old_at = datetime.now(UTC) - timedelta(days=60)
        recent_at = datetime.now(UTC) - timedelta(days=1)
        await _make_log(db, sent_at=old_at)
        await _make_log(db, sent_at=recent_at)
        await db.commit()

    await _purge_old_notification_logs()

    async with db_session_factory() as db:
        result = await db.execute(select(NotificationLog))
        remaining = list(result.scalars().all())
        assert len(remaining) == 1
        assert remaining[0].sent_at.replace(tzinfo=UTC) - recent_at < timedelta(seconds=5)


async def test_purge_old_notification_logs_skipped_when_retention_unset(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.notification_log_retention_days = None
        await _make_log(db, sent_at=datetime.now(UTC) - timedelta(days=9999))
        await db.commit()

    await _purge_old_notification_logs()

    async with db_session_factory() as db:
        result = await db.execute(select(NotificationLog))
        assert len(list(result.scalars().all())) == 1


async def test_notification_log_retention_setting_persists(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/settings/notification-log-retention",
        data={"retention_days": "45", "csrf_token": csrf_token},
    )
    assert response.status_code == 303

    page = await client.get("/settings?tab=checks")
    assert 'value="45"' in page.text
