"""Quiet hours and the daily summary of a notification rule
(`app.services.notification_timing`, `app.services.notification_digest`)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.app_settings import AppSettings
from app.db.models.machine import AuthMethod, Machine
from app.db.models.notification_log import (
    NotificationDeliveryStatus,
    NotificationHeldItem,
    NotificationLog,
)
from app.db.models.notification_rule import NotificationEventType, NotificationRule
from app.schemas.notification import NotificationRuleCreate
from app.services import notification_digest, notification_timing
from app.services import notifications as notifications_module
from app.services.notification_rules import apply_portable_rule, rule_to_portable_dict
from app.services.notifications import notify

E = NotificationEventType
SEC = NotificationEventType.SECURITY_UPDATES_AVAILABLE


def _rule(**kwargs: Any) -> NotificationRule:
    base: dict[str, Any] = {
        "name": "r",
        "enabled": True,
        "event_types": [E.MACHINE_UNREACHABLE.value],
        "delivery_channel": "webhook",
        "webhook_url": "https://hooks.example.com/abc",
        "quiet_hours_urgent": True,
        "digest_fleet_status": False,
    }
    base.update(kwargs)
    return NotificationRule(**base)


def _at(hour: int, minute: int = 0, day: int = 22) -> datetime:
    # Tests run with TZ unset, so the instance zone is UTC.
    return datetime(2026, 11, day, hour, minute, tzinfo=UTC)


def test_parse_and_normalize_hhmm() -> None:
    assert notification_timing.parse_hhmm("07:30") is not None
    assert notification_timing.parse_hhmm("7:30") is None
    assert notification_timing.parse_hhmm("24:00") is None
    assert notification_timing.normalize_hhmm("") is None
    assert notification_timing.normalize_hhmm(" 22:05 ") == "22:05"
    with pytest.raises(ValueError):
        notification_timing.normalize_hhmm("late")


def test_quiet_hours_cross_midnight() -> None:
    rule = _rule(quiet_hours_start="22:00", quiet_hours_end="07:00")
    assert notification_timing.in_quiet_hours(rule, _at(23, 30))
    assert notification_timing.in_quiet_hours(rule, _at(3))
    assert not notification_timing.in_quiet_hours(rule, _at(7))
    assert not notification_timing.in_quiet_hours(rule, _at(12))
    same_day = _rule(quiet_hours_start="12:00", quiet_hours_end="13:00")
    assert notification_timing.in_quiet_hours(same_day, _at(12, 30))
    assert not notification_timing.in_quiet_hours(same_day, _at(13))
    assert not notification_timing.in_quiet_hours(_rule(), _at(3))


def test_hold_reason_urgent_and_digest() -> None:
    quiet = _rule(quiet_hours_start="22:00", quiet_hours_end="07:00")
    night = _at(2)
    assert notification_timing.hold_reason(quiet, E.MACHINE_UNREACHABLE, None, night) is None
    assert notification_timing.hold_reason(quiet, SEC, None, night) == "quiet"
    assert notification_timing.hold_reason(quiet, SEC, None, _at(12)) is None
    # Health turning critical is urgent; a warning isn't.
    assert (
        notification_timing.hold_reason(quiet, E.HEALTH_DEGRADED, {"status": "critical"}, night)
        is None
    )
    assert (
        notification_timing.hold_reason(quiet, E.HEALTH_DEGRADED, {"status": "warning"}, night)
        == "quiet"
    )
    strict = _rule(quiet_hours_start="22:00", quiet_hours_end="07:00", quiet_hours_urgent=False)
    assert notification_timing.hold_reason(strict, E.MACHINE_UNREACHABLE, None, night) == "quiet"
    digest = _rule(digest_time="08:00")
    assert notification_timing.hold_reason(digest, SEC, None, _at(12)) == "digest"
    assert notification_timing.hold_reason(digest, E.MACHINE_UNREACHABLE, None, _at(12)) is None


def test_digest_due() -> None:
    quiet = _rule(quiet_hours_start="22:00", quiet_hours_end="07:00")
    assert not notification_timing.digest_due(quiet, _at(3), True)
    assert notification_timing.digest_due(quiet, _at(7, 1), True)
    assert not notification_timing.digest_due(quiet, _at(7, 1), False)

    daily = _rule(digest_time="08:00")
    assert notification_timing.digest_due(daily, _at(8, 1), True)
    assert not notification_timing.digest_due(daily, _at(8, 1), False)
    daily.digest_last_sent_at = datetime(2026, 11, 22, 8, 1)  # naive UTC, as stored
    assert not notification_timing.digest_due(daily, _at(20), True)
    assert notification_timing.digest_due(daily, _at(8, 0, day=23), True)
    daily.digest_fleet_status = True
    assert notification_timing.digest_due(daily, _at(8, 5, day=23), False)


def test_schema_validation() -> None:
    common: dict[str, Any] = {"name": "x", "event_types": [E.MACHINE_UNREACHABLE.value]}
    with pytest.raises(ValueError):
        NotificationRuleCreate(**common, quiet_hours_start="22:00")
    with pytest.raises(ValueError):
        NotificationRuleCreate(**common, quiet_hours_start="22:00", quiet_hours_end="22:00")
    with pytest.raises(ValueError):
        NotificationRuleCreate(**common, digest_fleet_status=True)
    with pytest.raises(ValueError):
        NotificationRuleCreate(**common, digest_time="8am")
    ok = NotificationRuleCreate(
        **common, quiet_hours_start="22:00", quiet_hours_end="07:00", digest_time="08:00"
    )
    assert ok.quiet_hours_urgent is True


async def test_portable_round_trip(db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        rule, _created = await apply_portable_rule(
            db,
            {
                "name": "night",
                "event_types": [SEC.value],
                "delivery_channel": "webhook",
                "webhook_url": "https://hooks.example.com/abc",
                "quiet_hours_start": "22:00",
                "quiet_hours_end": "07:00",
                "quiet_hours_urgent": False,
                "digest_time": "08:00",
                "digest_fleet_status": True,
            },
        )
        await db.commit()
        data = rule_to_portable_dict(rule, include_secrets=True)
        assert data["quiet_hours_start"] == "22:00"
        assert data["quiet_hours_end"] == "07:00"
        assert data["quiet_hours_urgent"] is False
        assert data["digest_time"] == "08:00"
        assert data["digest_fleet_status"] is True
        # A new summary time starts counting from now, not from the past.
        assert rule.digest_last_sent_at is not None
        with pytest.raises(ValueError):
            await apply_portable_rule(
                db,
                {
                    "name": "bad",
                    "event_types": [SEC.value],
                    "delivery_channel": "webhook",
                    "webhook_url": "https://hooks.example.com/abc",
                    # YAML reads an unquoted 7:30 as a number.
                    "digest_time": 450,
                },
            )


async def test_notify_holds_then_summary_sends(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted: list[dict[str, str]] = []

    async def _fake_post(
        url: str, event_type: str, rule_name: str, subject: str, body: str, context: Any
    ) -> tuple[NotificationDeliveryStatus, None]:
        posted.append({"event": event_type, "subject": subject, "body": body})
        return NotificationDeliveryStatus.SENT, None

    monkeypatch.setattr(notifications_module, "_send_webhook", _fake_post)

    async with db_session_factory() as db:
        machine = Machine(
            name="web10",
            ip_address="10.0.0.21",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            security_upgradable_count=3,
        )
        db.add(machine)
        rule = _rule(
            name="summary",
            event_types=[SEC.value, E.MACHINE_UNREACHABLE.value],
            digest_time="08:00",
            digest_fleet_status=True,
        )
        db.add(rule)
        db.add(AppSettings())
        await db.commit()

        await notify(db, SEC, machine=machine, context={"count": "5"})
        # Urgent: goes out at once even with a summary time.
        await notify(db, E.MACHINE_UNREACHABLE, machine=machine)

    assert [p["event"] for p in posted] == [E.MACHINE_UNREACHABLE.value]

    async with db_session_factory() as db:
        held = (await db.execute(select(NotificationHeldItem))).scalars().all()
        assert [h.event_type for h in held] == [SEC.value]
        assert held[0].reason == "digest"
        statuses = sorted(
            (await db.execute(select(NotificationLog.status))).scalars().all()
        )
        assert statuses == ["held", "sent"]

        sent = await notification_digest.send_due_digests(db, _at(8, 1, day=23))
        assert sent == 1

    assert len(posted) == 2
    summary = posted[1]
    assert summary["event"] == notification_digest.DIGEST_EVENT
    assert "1 held notification" in summary["subject"]
    assert "web10" in summary["body"]
    assert "3 security updates" in summary["body"]

    async with db_session_factory() as db:
        assert (await db.execute(select(NotificationHeldItem))).scalars().all() == []
        rule = (await db.execute(select(NotificationRule))).scalar_one()
        assert rule.digest_last_sent_at is not None
        # Sent today: not due again until tomorrow's 08:00.
        assert await notification_digest.send_due_digests(db, _at(9, 0, day=23)) == 0


def test_compose_localized_and_capped() -> None:
    rule = _rule(quiet_hours_start="22:00", quiet_hours_end="07:00")
    items = [
        NotificationHeldItem(
            event_type="no.such.event",
            context={},
            reason="quiet",
            created_at=datetime(2026, 11, 22, 2, 0),
        )
        for _ in range(notification_digest.MAX_LINES + 2)
    ]
    subject, body = notification_digest.compose(rule, items, {}, None, "cs")
    assert "Po tichých hodinách" in subject
    assert "a 2 další" in body
    _subject_en, body_en = notification_digest.compose(rule, [], {}, None, "en")
    assert "No notifications were held" in body_en


async def test_rule_form_saves_timing(client: Any, db_session_factory: Any) -> None:
    page = await client.get("/notifications/rules/new")
    assert page.status_code == 200
    assert 'name="quiet_hours_start"' in page.text
    csrf_token = client.cookies.get("csrftoken")
    bad = await client.post(
        "/notifications/rules",
        data={
            "name": "night",
            "event_types": [SEC.value],
            "delivery_channel": "webhook",
            "webhook_url": "https://hooks.example.com/abc",
            "quiet_hours_start": "22:00",
            "csrf_token": csrf_token,
        },
    )
    assert "both a start and an end" in bad.text
    response = await client.post(
        "/notifications/rules",
        data={
            "name": "night",
            "enabled": "1",
            "event_types": [SEC.value],
            "delivery_channel": "webhook",
            "webhook_url": "https://hooks.example.com/abc",
            "quiet_hours_start": "22:00",
            "quiet_hours_end": "07:00",
            "quiet_hours_urgent": "true",
            "digest_time": "08:00",
            "digest_fleet_status": "true",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        rule = (await db.execute(select(NotificationRule))).scalar_one()
        assert (rule.quiet_hours_start, rule.quiet_hours_end) == ("22:00", "07:00")
        assert rule.quiet_hours_urgent is True
        assert rule.digest_time == "08:00"
        assert rule.digest_fleet_status is True


async def test_one_failing_summary_does_not_stop_the_others(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    async def _fake_post(
        url: str, event_type: str, rule_name: str, subject: str, body: str, context: Any
    ) -> tuple[NotificationDeliveryStatus, None]:
        calls.append(rule_name)
        if rule_name == "a":
            raise RuntimeError("boom")
        return NotificationDeliveryStatus.SENT, None

    monkeypatch.setattr(notifications_module, "_send_webhook", _fake_post)
    async with db_session_factory() as db:
        db.add(AppSettings())
        for name in ("a", "b"):
            db.add(_rule(name=name, digest_time="08:00", digest_fleet_status=True))
        await db.commit()
        assert await notification_digest.send_due_digests(db, _at(8, 1)) == 1
    assert sorted(calls) == ["a", "b"]
