"""Tests for the write/action endpoints added to the REST API (Task 2) —
machines, machine groups, bulk actions, scheduling, users, roles, audit,
settings. Auth is a raw API token from `create_api_token`, mirroring
`tests/test_new_features.py`'s pattern for the pre-existing read-only API.
"""

from __future__ import annotations

import uuid

from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission, Role
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import User


async def _api_token(client: AsyncClient) -> dict[str, str]:
    import re

    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "api-test", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None
    return {"Authorization": f"Bearer {match.group(1)}"}


async def _create_machine(client: AsyncClient, headers: dict[str, str], name: str) -> str:
    response = await client.post(
        "/api/v1/machines",
        json={
            "name": name,
            "ip_address": "10.10.10.10",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
            "secret": "s3cret",
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def test_machine_crud_via_api(client, db_session_factory):
    headers = await _api_token(client)

    machine_id = await _create_machine(client, headers, "api-crud-machine")

    get_resp = await client.get(f"/api/v1/machines/{machine_id}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "api-crud-machine"

    put_resp = await client.put(
        f"/api/v1/machines/{machine_id}",
        json={
            "name": "renamed-machine",
            "ip_address": "10.10.10.10",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
            "is_active": True,
        },
        headers=headers,
    )
    assert put_resp.status_code == 200
    assert put_resp.json()["name"] == "renamed-machine"

    # Delete requires an exact confirm_name match.
    bad_delete = await client.request(
        "DELETE",
        f"/api/v1/machines/{machine_id}",
        json={"confirm_name": "wrong-name"},
        headers=headers,
    )
    assert bad_delete.status_code == 422

    good_delete = await client.request(
        "DELETE",
        f"/api/v1/machines/{machine_id}",
        json={"confirm_name": "renamed-machine"},
        headers=headers,
    )
    assert good_delete.status_code == 204

    async with db_session_factory() as db:
        assert await db.get(Machine, uuid.UUID(machine_id)) is None


async def test_machine_power_requires_pinned_host_key_and_confirm_name(client):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "power-machine")

    wrong_confirm = await client.post(
        f"/api/v1/machines/{machine_id}/power",
        json={"action": "reboot", "confirm_name": "not-the-name"},
        headers=headers,
    )
    assert wrong_confirm.status_code == 422

    # Right confirm name, but no pinned host key yet.
    no_fingerprint = await client.post(
        f"/api/v1/machines/{machine_id}/power",
        json={"action": "reboot", "confirm_name": "power-machine"},
        headers=headers,
    )
    assert no_fingerprint.status_code == 400


async def test_machine_updates_and_check_updates_via_api(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "update-machine")

    # System update requires a pinned host key.
    blocked = await client.post(
        f"/api/v1/machines/{machine_id}/updates",
        json={"strategy": "dist_upgrade"},
        headers=headers,
    )
    assert blocked.status_code == 400

    async with db_session_factory() as db:
        machine = await db.get(Machine, uuid.UUID(machine_id))
        assert machine is not None
        machine.host_key_fingerprint = "SHA256:abcdefg"
        await db.commit()

    ok = await client.post(
        f"/api/v1/machines/{machine_id}/updates",
        json={"strategy": "dist_upgrade"},
        headers=headers,
    )
    assert ok.status_code == 200
    assert ok.json()["status"] in ("pending", "running")

    check = await client.post(f"/api/v1/machines/{machine_id}/check-updates", headers=headers)
    assert check.status_code == 200


async def test_bulk_actions_via_api(client):
    headers = await _api_token(client)
    m1 = await _create_machine(client, headers, "bulk-1")
    m2 = await _create_machine(client, headers, "bulk-2")

    check = await client.post(
        "/api/v1/machines/bulk/check-updates",
        json={"machine_ids": [m1, m2]},
        headers=headers,
    )
    assert check.status_code == 200
    assert check.json()["machine_count"] == 2

    bad_power = await client.post(
        "/api/v1/machines/bulk/power",
        json={"machine_ids": [m1, m2], "action": "reboot", "confirm": "nope"},
        headers=headers,
    )
    assert bad_power.status_code == 422

    good_power = await client.post(
        "/api/v1/machines/bulk/power",
        json={"machine_ids": [m1, m2], "action": "reboot", "confirm": "SELECTED MACHINES"},
        headers=headers,
    )
    assert good_power.status_code == 200


async def test_machine_group_crud_and_membership_via_api(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "group-member-machine")

    create = await client.post(
        "/api/v1/machine-groups", json={"name": "api-group"}, headers=headers
    )
    assert create.status_code == 201
    group_id = create.json()["id"]

    add = await client.post(
        f"/api/v1/machine-groups/{group_id}/machines",
        json={"machine_id": machine_id},
        headers=headers,
    )
    assert add.status_code == 200

    members = await client.get(f"/api/v1/machine-groups/{group_id}/members", headers=headers)
    assert members.status_code == 200
    assert any(m["id"] == machine_id for m in members.json())

    update = await client.put(
        f"/api/v1/machine-groups/{group_id}",
        json={"name": "renamed-group"},
        headers=headers,
    )
    assert update.status_code == 200
    assert update.json()["name"] == "renamed-group"

    remove = await client.delete(
        f"/api/v1/machine-groups/{group_id}/machines/{machine_id}", headers=headers
    )
    assert remove.status_code == 204

    delete = await client.delete(f"/api/v1/machine-groups/{group_id}", headers=headers)
    assert delete.status_code == 204

    async with db_session_factory() as db:
        assert await db.get(MachineGroup, uuid.UUID(group_id)) is None


async def test_all_machines_check_updates_via_api(client):
    headers = await _api_token(client)
    await _create_machine(client, headers, "all-machines-target")
    response = await client.post("/api/v1/machine-groups/all/check-updates", headers=headers)
    assert response.status_code == 200


async def test_scheduling_crud_via_api(client, db_session_factory):
    headers = await _api_token(client)

    create = await client.post(
        "/api/v1/scheduling",
        json={
            "name": "api-schedule",
            "action": "check_updates",
            "target_type": "all_machines",
            "cron_expression": "0 3 * * *",
            "is_enabled": True,
        },
        headers=headers,
    )
    assert create.status_code == 201, create.text
    task_id = create.json()["id"]

    disable = await client.post(f"/api/v1/scheduling/{task_id}/disable", headers=headers)
    assert disable.status_code == 200
    assert disable.json()["is_enabled"] is False

    enable = await client.post(f"/api/v1/scheduling/{task_id}/enable", headers=headers)
    assert enable.status_code == 200
    assert enable.json()["is_enabled"] is True

    run_now = await client.post(f"/api/v1/scheduling/{task_id}/run-now", headers=headers)
    assert run_now.status_code == 200

    delete = await client.delete(f"/api/v1/scheduling/{task_id}", headers=headers)
    assert delete.status_code == 204

    async with db_session_factory() as db:
        assert await db.get(ScheduledTask, uuid.UUID(task_id)) is None


async def test_scheduling_run_history_via_api(
    client, db_session_factory, celery_calls, monkeypatch
):
    from app.scheduling.jobs import _run_scheduled_task

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    headers = await _api_token(client)

    create = await client.post(
        "/api/v1/scheduling",
        json={
            "name": "api-schedule-history",
            "action": "check_updates",
            "target_type": "all_machines",
            "cron_expression": "0 3 * * *",
            "is_enabled": True,
        },
        headers=headers,
    )
    assert create.status_code == 201, create.text
    task_id = create.json()["id"]

    empty = await client.get(f"/api/v1/scheduling/{task_id}/runs", headers=headers)
    assert empty.status_code == 200
    assert empty.json() == []

    result = await _run_scheduled_task(task_id)
    assert result["ok"] is True

    runs = await client.get(f"/api/v1/scheduling/{task_id}/runs", headers=headers)
    assert runs.status_code == 200
    body = runs.json()
    assert len(body) == 1
    assert body[0]["action"] == "check_updates"
    assert body[0]["status"] == "succeeded"


async def test_user_crud_via_api(client, db_session_factory):
    headers = await _api_token(client)

    async with db_session_factory() as db:
        role = (await db.execute(select(Role))).scalars().first()
        role_id = str(role.id)

    create = await client.post(
        "/api/v1/users",
        json={
            "username": "api-created-user",
            "auth_provider": "local",
            "password": "a-long-enough-password",
            "role_id": role_id,
        },
        headers=headers,
    )
    assert create.status_code == 201, create.text
    user_id = create.json()["id"]

    update = await client.put(
        f"/api/v1/users/{user_id}",
        json={
            "username": "api-created-user",
            "auth_provider": "local",
            "role_id": role_id,
            "is_active": True,
            "api_access_enabled": True,
        },
        headers=headers,
    )
    assert update.status_code == 200
    assert update.json()["api_access_enabled"] is True

    reset = await client.post(
        f"/api/v1/users/{user_id}/reset-password",
        json={"new_password": "another-long-password"},
        headers=headers,
    )
    assert reset.status_code == 200

    deactivate = await client.post(f"/api/v1/users/{user_id}/deactivate", headers=headers)
    assert deactivate.status_code == 200
    assert deactivate.json()["is_active"] is False

    delete = await client.request(
        "DELETE",
        f"/api/v1/users/{user_id}",
        json={"confirm_username": "api-created-user"},
        headers=headers,
    )
    assert delete.status_code == 204

    async with db_session_factory() as db:
        assert await db.get(User, uuid.UUID(user_id)) is None


async def test_user_api_update_to_duplicate_username_or_email_is_rejected(
    client, db_session_factory
):
    headers = await _api_token(client)

    async with db_session_factory() as db:
        role = (await db.execute(select(Role))).scalars().first()
        role_id = str(role.id)

    create_owner = await client.post(
        "/api/v1/users",
        json={
            "username": "api-owns-the-name",
            "email": "api-owns-the-email@example.com",
            "auth_provider": "ldap",
            "role_id": role_id,
        },
        headers=headers,
    )
    assert create_owner.status_code == 201, create_owner.text

    create_target = await client.post(
        "/api/v1/users",
        json={
            "username": "api-edit-target",
            "auth_provider": "ldap",
            "role_id": role_id,
        },
        headers=headers,
    )
    assert create_target.status_code == 201, create_target.text
    target_id = create_target.json()["id"]

    duplicate_username = await client.put(
        f"/api/v1/users/{target_id}",
        json={
            "username": "api-owns-the-name",
            "auth_provider": "ldap",
            "role_id": role_id,
            "is_active": True,
        },
        headers=headers,
    )
    assert duplicate_username.status_code == 409
    assert "already exists" in duplicate_username.json()["detail"]

    duplicate_email = await client.put(
        f"/api/v1/users/{target_id}",
        json={
            "username": "api-edit-target",
            "email": "api-owns-the-email@example.com",
            "auth_provider": "ldap",
            "role_id": role_id,
            "is_active": True,
        },
        headers=headers,
    )
    assert duplicate_email.status_code == 409
    assert "already in use" in duplicate_email.json()["detail"]


async def test_user_api_cannot_delete_self(client):
    headers = await _api_token(client)
    from tests.conftest import ADMIN_USERNAME

    me = await client.get("/api/v1/users", headers=headers)
    my_id = next(u["id"] for u in me.json() if u["username"] == ADMIN_USERNAME)

    response = await client.request(
        "DELETE",
        f"/api/v1/users/{my_id}",
        json={"confirm_username": ADMIN_USERNAME},
        headers=headers,
    )
    assert response.status_code == 403


async def test_role_crud_via_api(client, db_session_factory):
    headers = await _api_token(client)

    create = await client.post(
        "/api/v1/roles",
        json={"name": "api-role", "permissions": ["machine.view"]},
        headers=headers,
    )
    assert create.status_code == 201, create.text
    role_id = create.json()["id"]

    update = await client.put(
        f"/api/v1/roles/{role_id}",
        json={"name": "api-role-renamed", "permissions": ["machine.view", "group.view"]},
        headers=headers,
    )
    assert update.status_code == 200
    assert set(update.json()["permissions"]) == {"machine.view", "group.view"}

    delete = await client.delete(f"/api/v1/roles/{role_id}", headers=headers)
    assert delete.status_code == 204

    async with db_session_factory() as db:
        assert await db.get(Role, uuid.UUID(role_id)) is None


async def test_role_api_cannot_remove_last_user_manage(client, db_session_factory):
    headers = await _api_token(client)
    from tests.conftest import ADMIN_USERNAME

    async with db_session_factory() as db:
        result = await db.execute(select(User).where(User.username == ADMIN_USERNAME))
        admin = result.scalar_one()
        role_id = str(admin.role_id)

    response = await client.put(
        f"/api/v1/roles/{role_id}",
        json={"name": "stripped", "permissions": []},
        headers=headers,
    )
    assert response.status_code == 409


async def test_audit_log_list_and_export_via_api(client):
    headers = await _api_token(client)
    await _create_machine(client, headers, "audit-target-machine")

    listing = await client.get("/api/v1/audit", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["entries"]

    export = await client.get("/api/v1/audit/export?format=json", headers=headers)
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("application/json")


async def test_audit_log_api_filters_by_exact_target(client):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "api-target-a")
    await _create_machine(client, headers, "api-target-b")

    response = await client.get(
        f"/api/v1/audit?target_type=machine&target_id={machine_id}", headers=headers
    )

    assert response.status_code == 200
    entries = response.json()["entries"]
    assert entries
    assert all(e["target_id"] == machine_id for e in entries)
    assert any(e["target_label"] == "api-target-a" for e in entries)


async def test_settings_read_via_api(client):
    headers = await _api_token(client)
    response = await client.get("/api/v1/settings", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert "ssh_public_key" in body
    assert "app_version" in body


async def test_api_action_without_permission_is_rejected(client, login_as):
    await login_as(
        client, permissions={Permission.MACHINE_VIEW}, api_access_enabled=True
    )
    import re

    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "limited", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None
    headers = {"Authorization": f"Bearer {match.group(1)}"}

    response = await client.post(
        "/api/v1/machines",
        json={
            "name": "should-fail",
            "ip_address": "10.0.0.1",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
        },
        headers=headers,
    )
    assert response.status_code == 403


async def test_refresh_facts_packages_services_api_dispatch_the_right_tasks(
    client, db_session_factory, celery_calls
):
    from tests.test_onboarding import _make_machine

    machine_id = await _make_machine(db_session_factory)
    headers = await _api_token(client)

    facts_resp = await client.post(
        f"/api/v1/machines/{machine_id}/refresh-facts", headers=headers
    )
    packages_resp = await client.post(
        f"/api/v1/machines/{machine_id}/refresh-packages", headers=headers
    )
    services_resp = await client.post(
        f"/api/v1/machines/{machine_id}/refresh-services", headers=headers
    )

    assert facts_resp.status_code == 200, facts_resp.text
    assert packages_resp.status_code == 200, packages_resp.text
    assert services_resp.status_code == 200, services_resp.text
    assert "app.tasks.jobs.refresh_machine_facts" in celery_calls.names
    assert "app.tasks.jobs.refresh_machine_packages" in celery_calls.names
    assert "app.tasks.jobs.refresh_machine_services" in celery_calls.names


async def test_refresh_facts_api_reports_task_failure(client, db_session_factory, celery_calls):
    from tests.test_onboarding import _make_machine

    machine_id = await _make_machine(db_session_factory)
    headers = await _api_token(client)
    celery_calls.result_for["app.tasks.jobs.refresh_machine_facts"] = {
        "ok": False,
        "error": "boom",
    }

    response = await client.post(f"/api/v1/machines/{machine_id}/refresh-facts", headers=headers)

    assert response.status_code == 502
    assert "boom" in response.text


async def test_test_connection_api_dispatches_task(client, db_session_factory, celery_calls):
    from tests.test_onboarding import _make_machine

    machine_id = await _make_machine(db_session_factory)
    headers = await _api_token(client)

    response = await client.post(
        f"/api/v1/machines/{machine_id}/test-connection", headers=headers
    )

    assert response.status_code == 200, response.text
    assert celery_calls.names == ["app.tasks.jobs.test_machine_connection"]


async def test_discover_host_key_api(client, db_session_factory, monkeypatch):
    import app.web.routes.api_v1 as api_v1

    machine_id = await _create_machine(client, await _api_token(client), "discover-me")
    headers = await _api_token(client)

    async def _fake_discover(*args, **kwargs):
        return "SHA256:" + "a" * 43

    monkeypatch.setattr(api_v1, "discover_host_key_fingerprint", _fake_discover)

    response = await client.post(
        f"/api/v1/machines/{machine_id}/discover-host-key", headers=headers
    )

    assert response.status_code == 200, response.text
    assert response.json()["fingerprint"] == "SHA256:" + "a" * 43


async def test_trust_host_key_api_dispatches_facts_and_readiness(
    client, db_session_factory, celery_calls
):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "trust-me")

    response = await client.post(
        f"/api/v1/machines/{machine_id}/trust-host-key",
        json={"fingerprint": "SHA256:" + "b" * 43},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert "app.tasks.jobs.refresh_machine_facts" in celery_calls.names
    assert "app.tasks.jobs.check_machine_readiness" in celery_calls.names


async def test_trust_host_key_api_rejects_a_malformed_fingerprint(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await _create_machine(client, headers, "trust-bad")

    response = await client.post(
        f"/api/v1/machines/{machine_id}/trust-host-key",
        json={"fingerprint": "not a fingerprint"},
        headers=headers,
    )

    assert response.status_code == 400


async def test_run_onboarding_api_dispatches_readiness_on_success(
    client, db_session_factory, celery_calls
):
    from tests.test_onboarding import _make_machine

    machine_id = await _make_machine(db_session_factory)
    headers = await _api_token(client)

    response = await client.post(
        f"/api/v1/machines/{machine_id}/run-onboarding", headers=headers
    )

    assert response.status_code == 200, response.text
    assert "app.tasks.jobs.run_machine_onboarding" in celery_calls.names
    assert "app.tasks.jobs.check_machine_readiness" in celery_calls.names


async def test_fix_readiness_directly_api(client, db_session_factory, celery_calls):
    from tests.test_onboarding import _make_machine

    machine_id = await _make_machine(db_session_factory)
    headers = await _api_token(client)

    response = await client.post(
        f"/api/v1/machines/{machine_id}/fix-readiness-directly", headers=headers
    )

    assert response.status_code == 200, response.text
    assert celery_calls.names == ["app.tasks.jobs.fix_root_readiness"]


async def test_recheck_readiness_api(client, db_session_factory, celery_calls):
    from tests.test_onboarding import _make_machine

    machine_id = await _make_machine(db_session_factory)
    headers = await _api_token(client)

    response = await client.post(
        f"/api/v1/machines/{machine_id}/recheck-readiness", headers=headers
    )

    assert response.status_code == 200, response.text
    assert celery_calls.names == ["app.tasks.jobs.check_machine_readiness"]


async def test_logs_api_defaults_to_the_journal(client, db_session_factory, celery_calls):
    from tests.test_onboarding import _make_machine

    machine_id = await _make_machine(db_session_factory)
    headers = await _api_token(client)

    response = await client.get(f"/api/v1/machines/{machine_id}/logs", headers=headers)

    assert response.status_code == 200, response.text
    assert celery_calls.names == ["app.tasks.jobs.view_machine_journal"]
    assert "fake" in response.json()["output"]


async def test_logs_api_requires_terminal_permission(client, db_session_factory, login_as):
    from tests.test_onboarding import _make_machine

    machine_id = await _make_machine(db_session_factory)
    await login_as(
        client, permissions={Permission.MACHINE_VIEW}, api_access_enabled=True
    )
    headers = await _api_token(client)

    response = await client.get(f"/api/v1/machines/{machine_id}/logs", headers=headers)

    assert response.status_code == 403


async def test_logs_browse_api_defaults_to_the_first_allowed_path(
    client, db_session_factory, celery_calls
):
    from tests.test_onboarding import _make_machine

    machine_id = await _make_machine(db_session_factory)
    headers = await _api_token(client)
    celery_calls.result_for["app.tasks.jobs.browse_machine_log_directory"] = {
        "ok": True,
        "entries": [{"name": "syslog", "is_dir": False}],
    }

    response = await client.get(
        f"/api/v1/machines/{machine_id}/logs/browse", headers=headers
    )

    assert response.status_code == 200, response.text
    assert celery_calls.names == ["app.tasks.jobs.browse_machine_log_directory"]
    assert celery_calls[0][2]["path"] == "/var/log"
    body = response.json()
    assert body["path"] == "/var/log"
    assert body["entries"] == [{"name": "syslog", "is_dir": False}]


async def test_logs_browse_api_requires_terminal_permission(client, db_session_factory, login_as):
    from tests.test_onboarding import _make_machine

    machine_id = await _make_machine(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW}, api_access_enabled=True)
    headers = await _api_token(client)

    response = await client.get(
        f"/api/v1/machines/{machine_id}/logs/browse", headers=headers
    )

    assert response.status_code == 403


async def test_pending_machines_list_and_dismiss_api(client, db_session_factory):
    from app.db.models.pending_machine import PendingMachine

    async with db_session_factory() as session:
        pending = PendingMachine(ip_address="10.5.5.5", reported_hostname="fresh-box")
        session.add(pending)
        await session.commit()
        pending_id = pending.id

    headers = await _api_token(client)

    list_resp = await client.get("/api/v1/machines/pending", headers=headers)
    assert list_resp.status_code == 200
    assert any(p["id"] == str(pending_id) for p in list_resp.json())

    dismiss_resp = await client.post(
        f"/api/v1/machines/pending/{pending_id}/dismiss", headers=headers
    )
    assert dismiss_resp.status_code == 204

    list_after = await client.get("/api/v1/machines/pending", headers=headers)
    assert all(p["id"] != str(pending_id) for p in list_after.json())


async def test_api_actions_are_audit_logged_with_correct_actor(client, db_session_factory):
    """Verifies the fix to `get_api_token_user` — `request.state.user` is now
    set for `/api/` requests too, so `log_event`'s automatic actor
    resolution works the same way it does for cookie-session requests."""
    headers = await _api_token(client)
    await _create_machine(client, headers, "actor-check-machine")

    from tests.conftest import ADMIN_USERNAME

    async with db_session_factory() as db:
        result = await db.execute(
            select(AuditLogEntry)
            .where(AuditLogEntry.action == "machine.create")
            .order_by(AuditLogEntry.created_at.desc())
        )
        entry = result.scalars().first()
        assert entry is not None
        assert entry.actor == ADMIN_USERNAME


async def test_machine_list_is_ordered_and_pages_with_limit_offset(client):
    headers = await _api_token(client)
    for name in ("page-c", "page-a", "page-b"):
        await _create_machine(client, headers, name)

    everything = await client.get("/api/v1/machines", headers=headers)
    assert [m["name"] for m in everything.json()] == ["page-a", "page-b", "page-c"]

    page = await client.get("/api/v1/machines?limit=2&offset=1", headers=headers)
    assert [m["name"] for m in page.json()] == ["page-b", "page-c"]
    assert (await client.get("/api/v1/machines?limit=0", headers=headers)).status_code == 422
