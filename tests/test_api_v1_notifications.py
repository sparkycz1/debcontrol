"""REST API for Notifications (`app/web/routes/api_v1_notifications.py`) —
rules in the portable (YAML-export) shape, per-event and custom templates,
delivery history, permissions."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine_group import MachineGroup
from app.db.models.notification_rule import NotificationRule
from app.db.models.role import Permission
from tests.test_api_v1_extended import _api_token

_RULE = {
    "name": "api-rule",
    "description": "made over the API",
    "enabled": True,
    "event_types": ["machine.unreachable"],
    "conditions": [],
    "recipients": {"users": [], "roles": []},
    "scope": {"machines": [], "machine_groups": ["prod"]},
    "delivery_channel": "email",
}


async def test_rule_crud_round_trips_the_portable_shape(client, db_session_factory):
    async with db_session_factory() as session:
        session.add(MachineGroup(name="prod"))
        await session.commit()
    headers = await _api_token(client)

    created = await client.post("/api/v1/notifications/rules", json=_RULE, headers=headers)
    assert created.status_code == 201, created.text
    body = created.json()
    rule_id = body["id"]
    assert body["scope"]["machine_groups"] == ["prod"]
    assert body["event_types"] == ["machine.unreachable"]

    duplicate = await client.post("/api/v1/notifications/rules", json=_RULE, headers=headers)
    assert duplicate.status_code == 409

    listed = await client.get("/api/v1/notifications/rules", headers=headers)
    assert [r["name"] for r in listed.json()] == ["api-rule"]

    # Fetch → edit → PUT back, renaming it and adding a condition.
    fetched = (await client.get(f"/api/v1/notifications/rules/{rule_id}", headers=headers)).json()
    fetched.pop("id")
    fetched["name"] = "api-rule-renamed"
    fetched["conditions"] = [{"field": "monitoring.cpu_percent", "operator": "gt", "value": "90"}]
    updated = await client.put(
        f"/api/v1/notifications/rules/{rule_id}", json=fetched, headers=headers
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["name"] == "api-rule-renamed"
    assert updated.json()["conditions"][0]["field"] == "monitoring.cpu_percent"

    async with db_session_factory() as session:
        rule = await session.get(NotificationRule, uuid.UUID(updated.json()["id"]))
        # Conditions imply the condition_matched event, same as the form.
        assert "machine.condition_matched" in rule.event_types

    deleted = await client.delete(f"/api/v1/notifications/rules/{rule_id}", headers=headers)
    assert deleted.status_code == 204
    missing = await client.get(f"/api/v1/notifications/rules/{rule_id}", headers=headers)
    assert missing.status_code == 404

    async with db_session_factory() as session:
        actions = set(
            (await session.execute(select(AuditLogEntry.action))).scalars().all()
        )
    assert {
        "notification_rule.create",
        "notification_rule.update",
        "notification_rule.delete",
    } <= actions


async def test_invalid_rule_is_rejected_with_422(client):
    headers = await _api_token(client)
    response = await client.post(
        "/api/v1/notifications/rules",
        json={**_RULE, "event_types": ["no_such_event"]},
        headers=headers,
    )
    assert response.status_code == 422
    assert "no_such_event" in response.json()["detail"]


async def test_import_upserts_by_name_and_is_all_or_nothing(client, db_session_factory):
    headers = await _api_token(client)
    first = await client.post(
        "/api/v1/notifications/rules/import",
        json=[{**_RULE, "scope": {}}, {**_RULE, "name": "second", "scope": {}}],
        headers=headers,
    )
    assert first.json() == {"created": 2, "updated": 0}

    again = await client.post(
        "/api/v1/notifications/rules/import",
        json=[{**_RULE, "scope": {}, "enabled": False}],
        headers=headers,
    )
    assert again.json() == {"created": 0, "updated": 1}

    broken = await client.post(
        "/api/v1/notifications/rules/import",
        json=[{**_RULE, "name": "third", "scope": {}}, {"description": "no name"}],
        headers=headers,
    )
    assert broken.status_code == 422
    async with db_session_factory() as session:
        names = set((await session.execute(select(NotificationRule.name))).scalars().all())
    assert names == {"api-rule", "second"}


async def test_templates_override_and_reset(client):
    headers = await _api_token(client)
    listed = (await client.get("/api/v1/notifications/templates", headers=headers)).json()
    row = next(r for r in listed if r["event_type"] == "machine.unreachable")
    assert row["is_override"] is False
    assert row["subject"]

    put = await client.put(
        "/api/v1/notifications/templates/machine.unreachable",
        json={"subject": "Down: {machine_name}", "body": "{details}"},
        headers=headers,
    )
    assert put.status_code == 200
    listed = (await client.get("/api/v1/notifications/templates", headers=headers)).json()
    row = next(r for r in listed if r["event_type"] == "machine.unreachable")
    assert row == {
        "event_type": "machine.unreachable",
        "is_override": True,
        "subject": "Down: {machine_name}",
        "body": "{details}",
    }

    reset = await client.delete(
        "/api/v1/notifications/templates/machine.unreachable", headers=headers
    )
    assert reset.status_code == 204
    listed = (await client.get("/api/v1/notifications/templates", headers=headers)).json()
    assert not next(r for r in listed if r["event_type"] == "machine.unreachable")[
        "is_override"
    ]


async def test_custom_template_crud_and_rule_reference(client, db_session_factory):
    headers = await _api_token(client)
    created = await client.post(
        "/api/v1/notifications/custom-templates",
        json={"name": "short", "subject": "{event}", "body": "{details}"},
        headers=headers,
    )
    assert created.status_code == 201
    template_id = created.json()["id"]

    rule = await client.post(
        "/api/v1/notifications/rules",
        json={**_RULE, "scope": {}, "template_name": "short"},
        headers=headers,
    )
    assert rule.json()["template_name"] == "short"

    unknown = await client.post(
        "/api/v1/notifications/rules",
        json={**_RULE, "name": "other", "scope": {}, "template_name": "nope"},
        headers=headers,
    )
    assert unknown.status_code == 422

    deleted = await client.delete(
        f"/api/v1/notifications/custom-templates/{template_id}", headers=headers
    )
    assert deleted.status_code == 204
    after = await client.get(f"/api/v1/notifications/rules/{rule.json()['id']}", headers=headers)
    assert "template_name" not in after.json()


async def test_history_is_empty_and_paginates(client):
    headers = await _api_token(client)
    response = await client.get(
        "/api/v1/notifications/history?limit=5&offset=0", headers=headers
    )
    assert response.status_code == 200
    assert response.json() == []


async def test_view_permission_cannot_write(client, login_as):
    await login_as(client, permissions={Permission.NOTIFICATION_VIEW}, api_access_enabled=True)
    headers = await _api_token(client)
    assert (await client.get("/api/v1/notifications/rules", headers=headers)).status_code == 200
    response = await client.post("/api/v1/notifications/rules", json=_RULE, headers=headers)
    assert response.status_code == 403
