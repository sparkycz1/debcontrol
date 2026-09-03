"""The scheduled fleet summary — app.tasks.ai_jobs.generate_fleet_summary
(display-only, no notifications), its Settings AI-tab configuration, and
the Dashboard panel that shows the latest one.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

import app.tasks.ai_jobs as ai_jobs
from app.ai.base import ChatTurnResult
from app.core.app_settings import get_or_create_app_settings
from app.db.models.app_settings import FleetSummaryFrequency
from app.db.models.fleet_summary import FleetSummary
from app.db.models.machine import Machine
from app.db.models.role import Permission
from tests.test_ai_web import create_machine, setup_provider
from tests.test_dashboard_trends import _api_token


def test_fleet_summary_due_when_never_generated():
    now = datetime.now(UTC)
    assert ai_jobs._fleet_summary_due(None, FleetSummaryFrequency.DAILY, now) is True


def test_fleet_summary_daily_due_after_a_day():
    now = datetime.now(UTC)
    freq = FleetSummaryFrequency.DAILY
    assert ai_jobs._fleet_summary_due(now - timedelta(hours=2), freq, now) is False
    assert ai_jobs._fleet_summary_due(now - timedelta(hours=21), freq, now) is True


def test_fleet_summary_weekly_due_after_a_week():
    now = datetime.now(UTC)
    freq = FleetSummaryFrequency.WEEKLY
    assert ai_jobs._fleet_summary_due(now - timedelta(days=3), freq, now) is False
    assert ai_jobs._fleet_summary_due(now - timedelta(days=6, hours=21), freq, now) is True


def test_format_named_list_empty():
    assert ai_jobs._format_named_list([], 0) == "none"


def test_format_named_list_with_overflow():
    assert ai_jobs._format_named_list(["a", "b"], 5) == "a, b, and 3 more"


class _FakeSummaryClient:
    kind_value = "anthropic"

    def __init__(self, text: str = "Everything looks fine.") -> None:
        self.text = text
        self.calls: list[dict[str, Any]] = []

    async def send(self, messages, tools, model, system_prompt):  # noqa: ANN001 - test double
        self.calls.append({"messages": messages, "model": model, "system_prompt": system_prompt})
        return ChatTurnResult(text=self.text)

    def build_user_message(self, text: str) -> Any:
        return {"role": "user", "content": text}


async def _enable_fleet_summary(
    db_session_factory: Any,
    provider_id: uuid.UUID,
    model_id: str,
    *,
    frequency: FleetSummaryFrequency = FleetSummaryFrequency.DAILY,
) -> None:
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.fleet_summary_frequency = frequency
        app_settings.fleet_summary_provider_id = provider_id
        app_settings.fleet_summary_model_id = model_id
        await db.commit()


async def test_generate_fleet_summary_is_a_noop_when_disabled(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    await ai_jobs._generate_fleet_summary()

    async with db_session_factory() as db:
        count = (await db.execute(select(FleetSummary))).scalars().all()
        assert count == []


async def test_generate_fleet_summary_is_a_noop_without_a_configured_model(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.fleet_summary_frequency = FleetSummaryFrequency.DAILY
        await db.commit()

    await ai_jobs._generate_fleet_summary()

    async with db_session_factory() as db:
        assert (await db.execute(select(FleetSummary))).scalars().all() == []


async def test_generate_fleet_summary_writes_a_row_when_due(db_session_factory, monkeypatch):
    provider_id, model_id = await setup_provider(db_session_factory)
    await _enable_fleet_summary(db_session_factory, provider_id, model_id)
    machine_id = await create_machine(db_session_factory, name="offline1")
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        machine.is_reachable = False
        await db.commit()

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    fake = _FakeSummaryClient("Machine offline1 is down; nothing else needs attention.")
    monkeypatch.setattr(ai_jobs, "build_client", lambda config: fake)

    await ai_jobs._generate_fleet_summary()

    async with db_session_factory() as db:
        rows = (await db.execute(select(FleetSummary))).scalars().all()
        assert len(rows) == 1
        assert "offline1" in rows[0].content
        assert rows[0].frequency == "daily"
        assert rows[0].model_id == model_id
    assert len(fake.calls) == 1
    assert "offline1" in fake.calls[0]["messages"][0]["content"]


async def test_generate_fleet_summary_is_a_noop_when_not_due_yet(db_session_factory, monkeypatch):
    provider_id, model_id = await setup_provider(db_session_factory)
    await _enable_fleet_summary(db_session_factory, provider_id, model_id)
    async with db_session_factory() as db:
        db.add(
            FleetSummary(
                frequency="daily",
                content="Already generated recently.",
                provider_kind="anthropic",
                model_id=model_id,
            )
        )
        await db.commit()

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    fake = _FakeSummaryClient()
    monkeypatch.setattr(ai_jobs, "build_client", lambda config: fake)

    await ai_jobs._generate_fleet_summary()

    assert fake.calls == []
    async with db_session_factory() as db:
        rows = (await db.execute(select(FleetSummary))).scalars().all()
        assert len(rows) == 1  # still just the one seeded above


async def test_purge_old_fleet_summaries_respects_retention(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.fleet_summary_retention_days = 30
        old = FleetSummary(
            frequency="daily", content="old", provider_kind="anthropic", model_id="m"
        )
        db.add(old)
        await db.commit()
        old.created_at = datetime.now(UTC) - timedelta(days=45)
        await db.commit()
        db.add(
            FleetSummary(frequency="daily", content="new", provider_kind="anthropic", model_id="m")
        )
        await db.commit()

    await ai_jobs._purge_old_fleet_summaries()

    async with db_session_factory() as db:
        remaining = (await db.execute(select(FleetSummary))).scalars().all()
        assert [row.content for row in remaining] == ["new"]


async def test_settings_ai_tab_updates_fleet_summary_frequency(client, db_session_factory):
    provider_id, model_id = await setup_provider(db_session_factory)

    await client.get("/settings?tab=ai")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/fleet-summary",
        data={
            "frequency": "weekly",
            "provider_model": f"{provider_id}:{model_id}",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 303
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.fleet_summary_frequency == FleetSummaryFrequency.WEEKLY
        assert app_settings.fleet_summary_provider_id == provider_id
        assert app_settings.fleet_summary_model_id == model_id


async def test_settings_ai_tab_rejects_an_unenabled_model(client, db_session_factory):
    await client.get("/settings?tab=ai")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/fleet-summary",
        data={
            "frequency": "daily",
            "provider_model": f"{uuid.uuid4()}:not-a-real-model",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 200
    assert "isn&#39;t enabled" in response.text or "isn't enabled" in response.text


async def test_dashboard_shows_the_latest_fleet_summary(client, db_session_factory):
    async with db_session_factory() as db:
        db.add(
            FleetSummary(
                frequency="daily",
                content="All machines are healthy.",
                provider_kind="anthropic",
                model_id="claude-x",
            )
        )
        await db.commit()

    response = await client.get("/dashboard")

    assert "All machines are healthy." in response.text


async def test_fleet_summary_api_returns_the_latest_one(client, db_session_factory):
    async with db_session_factory() as db:
        db.add(
            FleetSummary(
                frequency="weekly",
                content="Fleet is healthy this week.",
                provider_kind="anthropic",
                model_id="claude-x",
            )
        )
        await db.commit()

    headers = await _api_token(client)
    response = await client.get("/api/v1/dashboard/fleet-summary", headers=headers)

    assert response.status_code == 200
    data = response.json()["summary"]
    assert data["content"] == "Fleet is healthy this week."
    assert data["frequency"] == "weekly"


async def test_fleet_summary_api_returns_none_when_never_generated(client):
    headers = await _api_token(client)
    response = await client.get("/api/v1/dashboard/fleet-summary", headers=headers)

    assert response.status_code == 200
    assert response.json()["summary"] is None


async def test_dashboard_hides_fleet_summary_from_a_restricted_account(
    client, db_session_factory, login_as
):
    async with db_session_factory() as db:
        db.add(
            FleetSummary(
                frequency="daily",
                content="Should not leak to a restricted account.",
                provider_kind="anthropic",
                model_id="claude-x",
            )
        )
        await db.commit()

    await login_as(
        client,
        permissions={Permission.MACHINE_VIEW},
        group_ids=[uuid.uuid4()],
    )

    response = await client.get("/dashboard")

    assert "Should not leak to a restricted account." not in response.text
