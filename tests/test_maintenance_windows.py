"""Maintenance windows: muting machine notifications, the web pages and
the REST API."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.notification_log import NotificationLog
from app.db.models.notification_rule import NotificationEventType, NotificationRule
from app.db.models.role import Permission
from app.db.models.user import User
from app.services.maintenance_windows import covers, window_state
from app.services.notifications import notify
from tests.test_api_v1_extended import _api_token
from tests.test_notifications import _make_role, _smtp_ready_settings

NOW = datetime.now(UTC)


def _window(**fields: object) -> MaintenanceWindow:
    defaults: dict[str, object] = {
        "name": "patching",
        "starts_at": NOW - timedelta(hours=1),
        "ends_at": NOW + timedelta(hours=1),
        "all_machines": False,
    }
    defaults.update(fields)
    window = MaintenanceWindow(**defaults)
    window.machines = []
    window.machine_groups = []
    return window


def test_window_state() -> None:
    assert window_state(_window()) == "active"
    assert window_state(_window(starts_at=NOW + timedelta(hours=1),
                                ends_at=NOW + timedelta(hours=2))) == "upcoming"
    assert window_state(_window(ends_at=NOW - timedelta(minutes=1))) == "ended"


def test_covers_by_group_machine_or_all() -> None:
    group = MachineGroup(id=uuid.uuid4(), name="prod")
    machine = Machine(id=uuid.uuid4(), name="web1", ip_address="10.0.0.1", username="u",
                      auth_method=AuthMethod.SSH_KEY)
    assert not covers(_window(), machine)
    assert covers(_window(all_machines=True), machine)
    listed = _window()
    listed.machines = [machine]
    assert covers(listed, machine)
    by_group = _window()
    by_group.machine_groups = [group]
    assert not covers(by_group, machine)
    machine.group_id = group.id
    assert covers(by_group, machine)


async def test_notify_is_suppressed_inside_an_active_window(db_session_factory, monkeypatch):
    sent: list[str] = []

    import app.services.notifications as notifications_module

    monkeypatch.setattr(
        notifications_module, "_send_smtp_message", lambda s, to, subj, body: sent.append(to)
    )
    async with db_session_factory() as db:
        db.add(_smtp_ready_settings())
        role = await _make_role(db, "ops")
        db.add(User(username="ops", auth_provider="local", email="ops@example.com", role=role))
        group = MachineGroup(name="prod")
        db.add(group)
        await db.flush()
        machine = Machine(name="web1", ip_address="10.0.0.1", username="u",
                          auth_method=AuthMethod.SSH_KEY, group_id=group.id)
        outside = Machine(name="db1", ip_address="10.0.0.2", username="u",
                          auth_method=AuthMethod.SSH_KEY)
        rule = NotificationRule(name="down", enabled=True,
                                event_types=[NotificationEventType.MACHINE_UNREACHABLE.value])
        rule.roles = [role]
        window = MaintenanceWindow(name="kernel patching", starts_at=NOW - timedelta(minutes=5),
                                   ends_at=NOW + timedelta(hours=1), all_machines=False)
        window.machine_groups = [group]
        db.add_all([machine, outside, rule, window])
        await db.commit()

        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=machine)
        assert sent == []
        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=outside)
        assert sent == ["ops@example.com"]

        logs = (await db.execute(select(NotificationLog))).scalars().all()
    suppressed = [log for log in logs if log.status == "suppressed"]
    assert len(suppressed) == 1
    assert suppressed[0].machine_name == "web1"
    assert "kernel patching" in suppressed[0].target


async def test_web_create_end_and_delete(client, db_session_factory):
    async with db_session_factory() as db:
        db.add(MachineGroup(name="prod"))
        await db.commit()
        group_id = (await db.execute(select(MachineGroup.id))).scalar_one()

    page = await client.get("/notifications/maintenance/new")
    assert page.status_code == 200
    csrf = client.cookies.get("csrftoken")
    start = (NOW - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M")
    end = (NOW + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M")

    bad = await client.post("/notifications/maintenance", data={
        "csrf_token": csrf, "name": "x", "starts_at": end, "ends_at": start,
        "machine_group_ids": str(group_id)})
    assert bad.status_code == 422
    assert "must end after it starts" in bad.text

    ok = await client.post("/notifications/maintenance", data={
        "csrf_token": csrf, "name": "Patch prod", "starts_at": start, "ends_at": end,
        "machine_group_ids": str(group_id)})
    assert ok.status_code == 303
    listing = await client.get("/notifications/maintenance")
    assert "Patch prod" in listing.text

    async with db_session_factory() as db:
        window = (await db.execute(select(MaintenanceWindow))).scalar_one()
        assert window_state(window) == "active"
        window_id = window.id

    ended = await client.post(f"/notifications/maintenance/{window_id}/end",
                              data={"csrf_token": csrf})
    assert ended.status_code == 303
    async with db_session_factory() as db:
        assert window_state(await db.get(MaintenanceWindow, window_id)) == "ended"

    deleted = await client.post(f"/notifications/maintenance/{window_id}/delete",
                                data={"csrf_token": csrf})
    assert deleted.status_code == 303
    async with db_session_factory() as db:
        assert (await db.execute(select(MaintenanceWindow))).first() is None
        actions = set((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert {"maintenance_window.create", "maintenance_window.end",
            "maintenance_window.delete"} <= actions


async def test_machine_page_shows_active_maintenance(client, db_session_factory):
    async with db_session_factory() as db:
        machine = Machine(name="web1", ip_address="10.0.0.1", username="u",
                          auth_method=AuthMethod.SSH_KEY)
        db.add(machine)
        await db.flush()
        db.add(MaintenanceWindow(name="all hands", starts_at=NOW - timedelta(minutes=1),
                                 ends_at=NOW + timedelta(hours=1), all_machines=True))
        await db.commit()
        machine_id = machine.id
    page = await client.get(f"/machines/{machine_id}")
    assert "all hands" in page.text


async def test_api_crud(client):
    headers = await _api_token(client)
    body = {"name": "deploy", "starts_at": NOW.isoformat(),
            "ends_at": (NOW + timedelta(minutes=30)).isoformat(), "all_machines": True}
    created = await client.post("/api/v1/notifications/maintenance-windows", json=body,
                                headers=headers)
    assert created.status_code == 201, created.text
    assert created.json()["state"] == "active"
    window_id = created.json()["id"]

    too_long = await client.post("/api/v1/notifications/maintenance-windows", headers=headers,
                                 json={**body, "ends_at": (NOW + timedelta(days=40)).isoformat()})
    assert too_long.status_code == 422
    no_scope = await client.post("/api/v1/notifications/maintenance-windows", headers=headers,
                                 json={**body, "all_machines": False})
    assert no_scope.status_code == 422

    ended = await client.post(f"/api/v1/notifications/maintenance-windows/{window_id}/end",
                              headers=headers)
    assert ended.json()["state"] == "ended"
    listed = await client.get("/api/v1/notifications/maintenance-windows", headers=headers)
    assert [w["name"] for w in listed.json()] == ["deploy"]
    deleted = await client.delete(f"/api/v1/notifications/maintenance-windows/{window_id}",
                                  headers=headers)
    assert deleted.status_code == 204


@pytest.mark.parametrize("perm", [Permission.NOTIFICATION_VIEW])
async def test_view_only_cannot_schedule(client, login_as, perm):
    await login_as(client, permissions={perm})
    assert (await client.get("/notifications/maintenance")).status_code == 200
    await client.get("/notifications")
    csrf = client.cookies.get("csrftoken")
    response = await client.post("/notifications/maintenance", data={"csrf_token": csrf})
    assert response.status_code == 403
