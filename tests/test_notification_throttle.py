"""A rule's throttle window (`NotificationRule.throttle_minutes`): at most
one notification per window for the same event about the same source, the
rest recorded as `throttled`, and the next real one saying how many were
held back."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, update

from app.db.models.machine import AuthMethod, Machine
from app.db.models.notification_log import NotificationDeliveryStatus, NotificationLog
from app.db.models.notification_rule import NotificationEventType, NotificationRule
from app.services import notifications as notifications_module
from app.services.notification_rules import rule_to_portable_dict
from app.services.notifications import notify


def _machine(name: str, ip: str) -> Machine:
    return Machine(
        name=name, ip_address=ip, port=22, username="root", auth_method=AuthMethod.PASSWORD
    )


def _capture_webhook(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    posted: list[dict[str, str]] = []

    async def _fake_post(
        url, event_type, rule_name, subject, body, context
    ):
        posted.append({"event": event_type, "body": body, **context})
        return NotificationDeliveryStatus.SENT, None

    monkeypatch.setattr(notifications_module, "_send_webhook", _fake_post)
    return posted


async def _statuses(db_session_factory: Any) -> list[str]:
    async with db_session_factory() as db:
        rows = (await db.execute(select(NotificationLog.status))).scalars().all()
    return sorted(rows)


async def test_throttled_rule_sends_once_per_window_and_source(db_session_factory, monkeypatch):
    posted = _capture_webhook(monkeypatch)
    async with db_session_factory() as db:
        web, mail = _machine("web1", "10.0.0.1"), _machine("mail1", "10.0.0.2")
        db.add_all([web, mail])
        db.add(
            NotificationRule(
                name="flappy",
                enabled=True,
                event_types=[
                    NotificationEventType.MACHINE_UNREACHABLE.value,
                    NotificationEventType.MACHINE_REACHABLE_AGAIN.value,
                ],
                delivery_channel="webhook",
                webhook_url="https://hooks.example.com/abc",
                throttle_minutes=30,
            )
        )
        await db.commit()

        for _ in range(3):
            await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=web)
        # Another machine and another event each have their own window.
        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=mail)
        await notify(db, NotificationEventType.MACHINE_REACHABLE_AGAIN, machine=web)

    assert len(posted) == 3
    assert await _statuses(db_session_factory) == ["sent", "sent", "sent", "throttled", "throttled"]


async def test_first_notification_after_the_window_reports_what_was_held_back(
    db_session_factory, monkeypatch
):
    posted = _capture_webhook(monkeypatch)
    async with db_session_factory() as db:
        web = _machine("web1", "10.0.0.1")
        db.add(web)
        db.add(
            NotificationRule(
                name="flappy",
                enabled=True,
                event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
                delivery_channel="webhook",
                webhook_url="https://hooks.example.com/abc",
                throttle_minutes=30,
            )
        )
        await db.commit()

        for _ in range(3):
            await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=web)
        # The window passes: everything so far happened 45 minutes ago.
        await db.execute(
            update(NotificationLog).values(sent_at=datetime.now(UTC) - timedelta(minutes=45))
        )
        await db.commit()
        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=web)

    assert len(posted) == 2
    assert "held_back" not in posted[0]
    assert posted[1]["held_back"] == "2"
    assert "2 more notification(s) like this were held back" in posted[1]["body"]


async def test_rule_without_a_window_sends_everything(db_session_factory, monkeypatch):
    posted = _capture_webhook(monkeypatch)
    async with db_session_factory() as db:
        web = _machine("web1", "10.0.0.1")
        db.add(web)
        db.add(
            NotificationRule(
                name="chatty",
                enabled=True,
                event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
                delivery_channel="webhook",
                webhook_url="https://hooks.example.com/abc",
            )
        )
        await db.commit()
        for _ in range(3):
            await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=web)

    assert len(posted) == 3


async def test_endpoint_checks_are_throttled_separately(db_session_factory, monkeypatch):
    posted = _capture_webhook(monkeypatch)
    async with db_session_factory() as db:
        db.add(
            NotificationRule(
                name="endpoints",
                enabled=True,
                event_types=[NotificationEventType.ENDPOINT_DOWN.value],
                delivery_channel="webhook",
                webhook_url="https://hooks.example.com/abc",
                throttle_minutes=30,
            )
        )
        await db.commit()
        for name in ("shop", "shop", "wiki"):
            await notify(
                db, NotificationEventType.ENDPOINT_DOWN, context={"endpoint_name": name}
            )

    assert [p["endpoint_name"] for p in posted] == ["shop", "wiki"]


async def test_rule_form_saves_and_shows_the_window(client, db_session_factory):
    await client.get("/notifications/rules/new")
    csrf_token = client.cookies.get("csrftoken")
    form = {
        "csrf_token": csrf_token,
        "name": "throttled rule",
        "enabled": "on",
        "event_types": [NotificationEventType.MACHINE_UNREACHABLE.value],
        "delivery_channel": "webhook",
        "webhook_url": "https://hooks.example.com/abc",
    }

    bad = await client.post("/notifications/rules", data={**form, "throttle_minutes": "soon"})
    assert bad.status_code == 422
    assert "whole number of minutes" in bad.text

    created = await client.post(
        "/notifications/rules", data={**form, "throttle_minutes": "15"}, follow_redirects=False
    )
    assert created.status_code == 303

    async with db_session_factory() as db:
        rule = (await db.execute(select(NotificationRule))).scalar_one()
        assert rule.throttle_minutes == 15
        assert rule_to_portable_dict(rule)["throttle_minutes"] == 15
        rule_id = rule.id

    page = await client.get(f"/notifications/rules/{rule_id}/edit")
    assert 'name="throttle_minutes"' in page.text
    assert 'value="15"' in page.text
