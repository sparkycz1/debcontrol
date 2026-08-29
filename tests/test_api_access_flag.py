"""Tests for `User.api_access_enabled` — a per-user, admin-set checkbox
distinct from the role-based Permission matrix, gating whether an account
can create/use API tokens at all.
"""

from __future__ import annotations

import re

from app.db.models.role import Permission
from app.db.models.user import User
from tests.conftest import create_local_user


async def test_admin_can_toggle_api_access_flag_on_edit(client, db_session_factory):
    user = await create_local_user(
        db_session_factory,
        username="flag-target",
        password="a-long-enough-password",
        permissions={Permission.MACHINE_VIEW},
    )
    assert user.api_access_enabled is False

    await client.get(f"/users/{user.id}/edit")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/users/{user.id}/edit",
        data={
            "username": user.username,
            "auth_provider": "local",
            "role_id": str(user.role_id),
            "is_active": "on",
            "api_access_enabled": "on",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        refreshed = await db.get(User, user.id)
        assert refreshed is not None
        assert refreshed.api_access_enabled is True

    # Unchecking it again turns it back off.
    response = await client.post(
        f"/users/{user.id}/edit",
        data={
            "username": user.username,
            "auth_provider": "local",
            "role_id": str(user.role_id),
            "is_active": "on",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        refreshed = await db.get(User, user.id)
        assert refreshed is not None
        assert refreshed.api_access_enabled is False


async def test_admin_can_set_api_access_flag_on_create(client, db_session_factory):
    await client.get("/roles")
    from sqlalchemy import select

    from app.db.models.role import Role

    async with db_session_factory() as db:
        role = (await db.execute(select(Role))).scalars().first()
        role_id = role.id

    await client.get("/users/new")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/users",
        data={
            "username": "new-with-api",
            "auth_provider": "local",
            "password": "a-long-enough-password",
            "role_id": str(role_id),
            "api_access_enabled": "on",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        result = await db.execute(select(User).where(User.username == "new-with-api"))
        created = result.scalar_one()
        assert created.api_access_enabled is True


async def test_user_without_api_access_cannot_create_token(client, login_as):
    await login_as(client, permissions=set(Permission), api_access_enabled=False)
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "should-fail", "csrf_token": csrf_token}
    )
    assert response.status_code == 403


async def test_user_with_api_access_can_create_token(client, login_as):
    await login_as(client, permissions=set(Permission), api_access_enabled=True)
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "should-work", "csrf_token": csrf_token}
    )
    assert response.status_code == 200
    assert re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)


async def test_existing_token_stops_working_after_flag_disabled(client, db_session_factory):
    # Create a token while api_access_enabled=True (the `client` fixture's default).
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "will-be-cut-off", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None
    raw_token = match.group(1)
    headers = {"Authorization": f"Bearer {raw_token}"}

    assert (await client.get("/api/v1/machines", headers=headers)).status_code == 200

    from tests.conftest import ADMIN_USERNAME

    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(User).where(User.username == ADMIN_USERNAME))
        admin = result.scalar_one()
        admin.api_access_enabled = False
        await db.commit()

    response = await client.get("/api/v1/machines", headers=headers)
    assert response.status_code == 401
