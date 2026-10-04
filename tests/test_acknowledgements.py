"""Acknowledging a problem on a machine or an endpoint check
(`app.services.acknowledgements`): what it withholds, what ends it, and the
web and REST routes around it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine import AuthMethod, Machine
from app.db.models.notification_log import NotificationDeliveryStatus, NotificationLog
from app.db.models.notification_rule import NotificationEventType, NotificationRule
from app.services import acknowledgements
from app.services import notifications as notifications_module
from app.services.endpoint_checks import ProbeResult, apply_result
from app.services.notifications import notify
from tests.test_api_v1_extended import _api_token


def _machine(name: str = "web1") -> Machine:
    return Machine(
        name=name, ip_address="10.0.0.1", port=22, username="root", auth_method=AuthMethod.PASSWORD
    )


def _check(name: str = "shop") -> EndpointCheck:
    return EndpointCheck(name=name, kind="http", target="https://shop.example.com")


def _rule(*events: NotificationEventType) -> NotificationRule:
    return NotificationRule(
        name="all",
        enabled=True,
        event_types=[event.value for event in events],
        delivery_channel="webhook",
        webhook_url="https://hooks.example.com/abc",
    )


def _capture_webhook(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    posted: list[str] = []

    async def _fake_post(*args: Any) -> tuple[NotificationDeliveryStatus, None]:
        posted.append(args[1])
        return NotificationDeliveryStatus.SENT, None

    monkeypatch.setattr(notifications_module, "_send_webhook", _fake_post)
    return posted


def test_an_acknowledgement_is_active_until_its_end_time() -> None:
    machine = _machine()
    now = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
    assert not acknowledgements.is_active(machine, now)

    acknowledgements.acknowledge(machine, by="alice", note=" disk on order ", hours=8, now=now)
    assert machine.acknowledged_note == "disk on order"
    assert acknowledgements.is_active(machine, now + timedelta(hours=7))
    assert not acknowledgements.is_active(machine, now + timedelta(hours=8))

    acknowledgements.acknowledge(machine, by="alice", note=None, hours=None, now=now)
    assert acknowledgements.is_active(machine, now + timedelta(days=400))

    acknowledgements.clear(machine)
    assert not acknowledgements.is_active(machine, now)
    with pytest.raises(ValueError):
        acknowledgements.acknowledge(machine, by="alice", note=None, hours=0)
    with pytest.raises(ValueError):
        acknowledgements.hours_for("forever")


async def test_acknowledged_machine_withholds_problems_but_not_recovery(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted = _capture_webhook(monkeypatch)
    async with db_session_factory() as db:
        machine = _machine()
        db.add(machine)
        db.add(
            _rule(
                NotificationEventType.MACHINE_UNREACHABLE,
                NotificationEventType.SERVICE_FAILED,
                NotificationEventType.MACHINE_REACHABLE_AGAIN,
                NotificationEventType.UPDATE_RUN_FAILED,
            )
        )
        await db.commit()
        acknowledgements.acknowledge(machine, by="alice", note="known", hours=None)
        await db.commit()

        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=machine)
        await notify(db, NotificationEventType.SERVICE_FAILED, machine=machine)
        # The result of an update someone started is not "the problem".
        await notify(db, NotificationEventType.UPDATE_RUN_FAILED, machine=machine)
        await notify(db, NotificationEventType.MACHINE_REACHABLE_AGAIN, machine=machine)

        logs = (await db.execute(select(NotificationLog))).scalars().all()

    assert posted == ["machine.update_run.failed", "machine.reachable_again"]
    suppressed = [log for log in logs if log.status == "suppressed"]
    assert len(suppressed) == 2
    assert {log.target for log in suppressed} == {"acknowledged by alice"}


async def test_an_expired_acknowledgement_withholds_nothing(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted = _capture_webhook(monkeypatch)
    async with db_session_factory() as db:
        machine = _machine()
        db.add_all([machine, _rule(NotificationEventType.MACHINE_UNREACHABLE)])
        await db.commit()
        acknowledgements.acknowledge(
            machine,
            by="alice",
            note=None,
            hours=1,
            now=datetime.now(UTC) - timedelta(hours=2),
        )
        await db.commit()
        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=machine)

    assert posted == ["machine.unreachable"]


async def test_acknowledged_check_withholds_and_recovery_clears_it(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted = _capture_webhook(monkeypatch)
    async with db_session_factory() as db:
        check = _check()
        db.add_all([check, _rule(NotificationEventType.ENDPOINT_DOWN)])
        await db.commit()
        acknowledgements.acknowledge(check, by="bob", note=None, hours=None)
        await db.commit()

        await notify(
            db,
            NotificationEventType.ENDPOINT_DOWN,
            context={"endpoint_name": check.name},
            check=check,
        )
        assert posted == []

        apply_result(check, ProbeResult(ok=True), datetime.now(UTC))
        assert check.acknowledged_at is None


async def test_web_acknowledge_and_clear_a_machine(client: Any, db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        machine = _machine()
        db.add(machine)
        await db.commit()
        machine_id = machine.id

    page = await client.get(f"/machines/{machine_id}")
    assert f'action="/machines/{machine_id}/acknowledge"' in page.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}

    bad = await client.post(
        f"/machines/{machine_id}/acknowledge", data={**csrf, "duration": "forever"}
    )
    assert bad.status_code == 422
    done = await client.post(
        f"/machines/{machine_id}/acknowledge",
        data={**csrf, "duration": "8h", "note": "disk on order"},
        follow_redirects=False,
    )
    assert done.status_code == 303

    page = await client.get(f"/machines/{machine_id}")
    assert "disk on order" in page.text
    assert f'action="/machines/{machine_id}/acknowledge/clear"' in page.text
    assert "acknowledged" in (await client.get("/machines")).text

    cleared = await client.post(
        f"/machines/{machine_id}/acknowledge/clear", data=csrf, follow_redirects=False
    )
    assert cleared.status_code == 303
    async with db_session_factory() as db:
        assert (await db.get(Machine, machine_id)).acknowledged_at is None


async def test_web_acknowledge_a_check(client: Any, db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        check = _check()
        db.add(check)
        await db.commit()
        check_id = check.id

    page = await client.get(f"/checks/{check_id}")
    assert f'action="/checks/{check_id}/acknowledge"' in page.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}
    done = await client.post(
        f"/checks/{check_id}/acknowledge",
        data={**csrf, "duration": "until_recovered", "note": "provider outage"},
        follow_redirects=False,
    )
    assert done.status_code == 303
    assert "provider outage" in (await client.get(f"/checks/{check_id}")).text
    assert "acknowledged" in (await client.get("/checks")).text

    cleared = await client.post(
        f"/checks/{check_id}/acknowledge/clear", data=csrf, follow_redirects=False
    )
    assert cleared.status_code == 303
    async with db_session_factory() as db:
        assert (await db.get(EndpointCheck, check_id)).acknowledged_at is None


async def test_api_acknowledge(client: Any, db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        machine, check = _machine(), _check()
        db.add_all([machine, check])
        await db.commit()
        machine_id, check_id = machine.id, check.id
    headers = await _api_token(client)

    for base in (f"/api/v1/machines/{machine_id}", f"/api/v1/checks/{check_id}"):
        too_long = await client.post(
            f"{base}/acknowledge", json={"hours": 100000}, headers=headers
        )
        assert too_long.status_code == 422
        done = await client.post(
            f"{base}/acknowledge", json={"hours": 4, "note": "known"}, headers=headers
        )
        assert done.status_code == 200
        body = done.json()["acknowledgement"]
        assert body["note"] == "known" and body["until"] is not None and body["by"]
        cleared = await client.delete(f"{base}/acknowledge", headers=headers)
        assert cleared.status_code == 204

    shown = (await client.get(f"/api/v1/machines/{machine_id}", headers=headers)).json()
    assert shown["acknowledgement"] is None
