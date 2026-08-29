from __future__ import annotations

import re

from httpx import AsyncClient

from app.db.models.role import Permission


def _extract_role_id(roles_page_html: str) -> str:
    match = re.search(r"/roles/([0-9a-f-]{36})/edit", roles_page_html)
    assert match is not None, roles_page_html
    return match.group(1)


async def test_create_role_with_permissions(client):
    await client.get("/roles/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/roles",
        data={
            "name": "Operator",
            "description": "Runs updates, nothing else.",
            "permissions": [Permission.MACHINE_VIEW.value, Permission.ACTION_UPDATES.value],
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303

    roles_page = await client.get("/roles")
    assert "Operator" in roles_page.text


async def test_duplicate_role_name_is_rejected(client):
    await client.get("/roles/new")
    csrf_token = client.cookies.get("csrftoken")
    data = {"name": "Duplicate", "description": "", "permissions": [], "csrf_token": csrf_token}
    first = await client.post("/roles", data=data)
    assert first.status_code == 303

    csrf_token = client.cookies.get("csrftoken")
    data["csrf_token"] = csrf_token
    second = await client.post("/roles", data=data)
    assert second.status_code == 409


async def test_role_cannot_be_deleted_while_assigned_to_a_user(client):
    await client.get("/roles/new")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/roles",
        data={
            "name": "In Use",
            "description": "",
            "permissions": [Permission.MACHINE_VIEW.value],
            "csrf_token": csrf_token,
        },
    )
    roles_page = await client.get("/roles")
    role_id = _extract_role_id(roles_page.text)

    await client.get("/users/new")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/users",
        data={
            "username": "role-holder",
            "display_name": "",
            "auth_provider": "ldap",
            "password": "",
            "role_id": role_id,
            "csrf_token": csrf_token,
        },
    )

    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(f"/roles/{role_id}/delete", data={"csrf_token": csrf_token})
    assert response.status_code == 409


async def test_create_local_user_requires_a_password(client):
    roles_page = await client.get("/roles")
    role_id = _extract_role_id(roles_page.text)

    await client.get("/users/new")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/users",
        data={
            "username": "no-password-local",
            "display_name": "",
            "auth_provider": "local",
            "password": "",
            "role_id": role_id,
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 422
    assert "needs a password" in response.text


async def test_create_ldap_user_forbids_a_password(client):
    roles_page = await client.get("/roles")
    role_id = _extract_role_id(roles_page.text)

    await client.get("/users/new")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/users",
        data={
            "username": "ldap-with-password",
            "display_name": "",
            "auth_provider": "ldap",
            "password": "some-password-123",
            "role_id": role_id,
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 422
    # Jinja escapes the apostrophe in "don't" as `&#39;` — assert around it.
    assert "accounts don" in response.text and "set a password here" in response.text


async def test_duplicate_username_is_rejected(client: AsyncClient) -> None:
    roles_page = await client.get("/roles")
    role_id = _extract_role_id(roles_page.text)

    async def _create(username: str) -> int:
        await client.get("/users/new")
        csrf_token = client.cookies.get("csrftoken")
        response = await client.post(
            "/users",
            data={
                "username": username,
                "display_name": "",
                "auth_provider": "ldap",
                "password": "",
                "role_id": role_id,
                "csrf_token": csrf_token,
            },
        )
        return response.status_code

    assert await _create("dupe-user") == 303
    assert await _create("dupe-user") == 409


async def test_created_local_user_can_log_in_with_correct_permissions(
    anonymous_client, client, db_session_factory
):
    roles_page = await client.get("/roles")
    role_id = _extract_role_id(roles_page.text)

    await client.get("/users/new")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/users",
        data={
            "username": "new-local-user",
            "display_name": "",
            "auth_provider": "local",
            "password": "a-brand-new-password-1",
            "role_id": role_id,
            "csrf_token": csrf_token,
        },
    )

    await anonymous_client.get("/login")
    login_csrf = anonymous_client.cookies.get("csrftoken")
    login = await anonymous_client.post(
        "/login",
        data={
            "username": "new-local-user",
            "password": "a-brand-new-password-1",
            "csrf_token": login_csrf,
        },
    )
    # An admin-set password forces a change before anything else.
    assert login.status_code == 303
    assert login.headers["location"] == "/account"


async def test_admin_reset_password_forces_change_and_revokes_sessions(
    anonymous_client, client, db_session_factory
):
    from tests.conftest import create_local_user

    target = await create_local_user(
        db_session_factory, username="needs-reset", password="original-password-123"
    )

    await anonymous_client.get("/login")
    login_csrf = anonymous_client.cookies.get("csrftoken")
    await anonymous_client.post(
        "/login",
        data={
            "username": "needs-reset",
            "password": "original-password-123",
            "csrf_token": login_csrf,
        },
    )
    assert (await anonymous_client.get("/account")).status_code == 200

    edit_page = await client.get(f"/users/{target.id}/edit")
    assert edit_page.status_code == 200
    csrf_token = client.cookies.get("csrftoken")
    reset = await client.post(
        f"/users/{target.id}/reset-password",
        data={"new_password": "a-completely-new-password-1", "csrf_token": csrf_token},
    )
    assert reset.status_code == 303

    # The old session is dead — signed out everywhere.
    assert (await anonymous_client.get("/account")).status_code == 303

    login_csrf = await _fresh_csrf(anonymous_client)
    relogin = await anonymous_client.post(
        "/login",
        data={
            "username": "needs-reset",
            "password": "a-completely-new-password-1",
            "csrf_token": login_csrf,
        },
    )
    assert relogin.status_code == 303
    assert relogin.headers["location"] == "/account"  # must_change_password again


async def _fresh_csrf(client: AsyncClient) -> str:
    await client.get("/login")
    token = client.cookies.get("csrftoken")
    assert token is not None
    return token
