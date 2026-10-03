from __future__ import annotations


async def test_audit_log_empty_state(client):
    response = await client.get("/audit")
    assert response.status_code == 200
    assert "No audit log entries" in response.text


async def test_audit_nav_link_present(client):
    response = await client.get("/machines")
    assert 'href="/audit"' in response.text


async def test_creating_machine_writes_audit_entry(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    await client.post(
        "/machines",
        data={
            "name": "audit-me",
            "ip_address": "10.9.9.1",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )

    log = await client.get("/audit")
    assert log.status_code == 200
    assert "machine.create" in log.text
    assert "audit-me" in log.text
    # httpx2's ASGITransport reports a fixed client address for test requests.
    assert "127.0.0.1" in log.text
    assert "badge-ok" in log.text  # success outcome

    from tests.conftest import ADMIN_USERNAME

    assert ADMIN_USERNAME in log.text  # the logged-in actor


async def test_audit_log_search_filters_entries(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    await client.post(
        "/machines",
        data={
            "name": "findme",
            "ip_address": "10.9.9.2",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    await client.post(
        "/machines",
        data={
            "name": "other",
            "ip_address": "10.9.9.3",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )

    filtered = await client.get("/audit?q=findme")
    assert "findme" in filtered.text
    assert "other" not in filtered.text


async def test_denied_power_confirmation_is_logged_as_denied(client, db_session_factory):
    from tests.test_web import _create_machine, _pin_host_key

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="power-audit")
    await _pin_host_key(db_session_factory, machine_id)

    await client.post(
        f"/machines/{machine_id}/power",
        data={"action": "reboot", "confirm_name": "not-the-name", "csrf_token": csrf_token},
    )

    log = await client.get("/audit?outcome=denied")
    assert log.status_code == 200
    assert "machine.power.reboot" in log.text
    assert "badge-error" in log.text


async def test_deleting_machine_writes_audit_entry_with_target_label(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    create = await client.post(
        "/machines",
        data={
            "name": "delete-me",
            "ip_address": "10.9.9.4",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    machine_url = create.headers["location"]

    await client.post(f"{machine_url}/delete", data={"csrf_token": csrf_token})

    log = await client.get("/audit")
    assert "machine.delete" in log.text
    assert "delete-me" in log.text


async def test_rejected_machine_creation_is_logged_as_failure(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines",
        data={
            "name": "bad-ip",
            "ip_address": "not-an-ip",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 422

    log = await client.get("/audit?outcome=failure")
    assert "machine.create" in log.text
    assert "bad-ip" in log.text
    assert "badge-warn" in log.text  # failure outcome


async def test_duplicate_group_name_is_logged_as_failure(client):
    await client.get("/machine-groups/new")
    csrf_token = client.cookies.get("csrftoken")

    await client.post(
        "/machine-groups", data={"name": "dupe", "description": "", "csrf_token": csrf_token}
    )
    dupe = await client.post(
        "/machine-groups", data={"name": "dupe", "description": "", "csrf_token": csrf_token}
    )
    assert dupe.status_code == 409

    log = await client.get("/audit?outcome=failure")
    assert "group.create" in log.text
    assert "already exists" in log.text


async def test_scheduled_task_lifecycle_writes_audit_entries(client):
    await client.get("/scheduling/new")
    csrf_token = client.cookies.get("csrftoken")

    await client.post(
        "/scheduling",
        data={
            "name": "audited-schedule",
            "target": "all",
            "action": "check_updates",
            "cron_expression": "0 3 * * *",
            "is_enabled": "on",
            "csrf_token": csrf_token,
        },
    )

    log = await client.get("/audit")
    assert "scheduled_task.create" in log.text
    assert "audited-schedule" in log.text


async def test_self_registration_with_bad_token_is_logged_as_denied(client):
    response = await client.post(
        "/api/inform",
        json={"hostname": "h"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401

    log = await client.get("/audit?outcome=denied")
    assert "machine.self_register" in log.text


async def test_self_registration_with_valid_token_is_logged_as_success(client):
    from app.core.config import get_settings

    token = get_settings().inform_token.get_secret_value()
    response = await client.post(
        "/api/inform",
        json={"hostname": "h", "ip_address": "10.9.9.9"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201

    log = await client.get("/audit")
    assert "machine.self_register" in log.text
    assert "10.9.9.9" in log.text


async def test_successful_login_is_logged(anonymous_client, db_session_factory):
    from app.db.models.role import Permission
    from tests.conftest import create_local_user

    await create_local_user(
        db_session_factory,
        username="audited-user",
        password="a-very-good-password-123",
        permissions={Permission.AUDIT_VIEW},
    )
    await anonymous_client.get("/login")
    csrf_token = anonymous_client.cookies.get("csrftoken")
    await anonymous_client.post(
        "/login",
        data={
            "username": "audited-user",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )

    log = await anonymous_client.get("/audit")
    assert log.status_code == 200
    assert "user.login" in log.text
    assert "audited-user" in log.text
    assert "127.0.0.1" in log.text


async def test_failed_login_is_logged_as_denied(anonymous_client, db_session_factory):
    from app.db.models.role import Permission
    from tests.conftest import create_local_user

    # An account that can view the audit log, so it's the one checking it —
    # the *failed* login attempt below is for a different, nonexistent user.
    await create_local_user(
        db_session_factory,
        username="auditor",
        password="a-very-good-password-123",
        permissions={Permission.AUDIT_VIEW},
    )
    await anonymous_client.get("/login")
    csrf_token = anonymous_client.cookies.get("csrftoken")
    await anonymous_client.post(
        "/login", data={"username": "nobody-at-all", "password": "wrong", "csrf_token": csrf_token}
    )

    csrf_token = anonymous_client.cookies.get("csrftoken")
    await anonymous_client.post(
        "/login",
        data={
            "username": "auditor",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )

    log = await anonymous_client.get("/audit?outcome=denied")
    assert "user.login" in log.text
    assert "nobody-at-all" in log.text


async def test_creating_a_user_writes_an_audit_entry(client):
    import re

    await client.get("/roles")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/roles",
        data={
            "name": "Auditable Role",
            "description": "",
            "permissions": [],
            "csrf_token": csrf_token,
        },
    )
    roles_page = await client.get("/roles")
    match = re.search(r"/roles/([0-9a-f-]{36})/edit", roles_page.text)
    assert match is not None
    role_id = match.group(1)

    await client.get("/users/new")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/users",
        data={
            "username": "audited-new-user",
            "display_name": "",
            "auth_provider": "ldap",
            "password": "",
            "role_id": role_id,
            "csrf_token": csrf_token,
        },
    )

    log = await client.get("/audit")
    assert "user.create" in log.text
    assert "audited-new-user" in log.text
    assert "role.create" in log.text


async def test_machine_history_tab_links_to_its_own_audit_history(client):
    from tests.test_web import _create_machine

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="linked-machine")

    # The link sits on the History tab (which leaves read-only look-ups
    # out), not in the Overview header any more.
    history = await client.get(f"/machines/{machine_id}/history")
    assert f"/audit?target_type=machine&target_id={machine_id}" in history.text


async def test_audit_log_filters_by_exact_machine_target(client, db_session_factory):
    from tests.test_web import _create_machine

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="target-a")
    await _create_machine(client, csrf_token, name="target-b")

    response = await client.get(f"/audit?target_type=machine&target_id={machine_id}")

    assert response.status_code == 200
    assert "target-a" in response.text
    assert "target-b" not in response.text
    assert f'value="{machine_id}"' in response.text  # hidden target_id carried through the form


async def test_audit_log_target_filter_banner_and_clear_link(client, db_session_factory):
    from tests.test_web import _create_machine

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="banner-machine")

    response = await client.get(f"/audit?target_type=machine&target_id={machine_id}")

    assert "Showing entries for machine" in response.text
    assert "banner-machine" in response.text
    assert 'href="/audit?q=&outcome="' in response.text


async def test_audit_export_respects_target_filter(client, db_session_factory):
    from tests.test_web import _create_machine

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="export-target")
    await _create_machine(client, csrf_token, name="export-other")

    response = await client.get(
        f"/audit/export?format=json&target_type=machine&target_id={machine_id}"
    )

    assert response.status_code == 200
    assert "export-target" in response.text
    assert "export-other" not in response.text
