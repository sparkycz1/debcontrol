"""Bulk actions on the user list (`/users/bulk/...`) — deactivate,
activate, force sign-out, and set-role for an ad-hoc checkbox selection,
mirroring the machine list's own bulk actions. See
`app/web/routes/users.py`'s "Bulk actions" section for why none of these
need their own "last admin" guard: the acting account (which must hold
`user.manage` to reach any of these routes at all) is never in the batch.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.db.models.role import Permission, Role, RolePermission
from app.db.models.user import AuthProvider, User


async def _make_user(
    db_session_factory: Any, *, username: str, is_active: bool = True
) -> uuid.UUID:
    async with db_session_factory() as session:
        role = Role(name=f"role-for-{username}")
        role.permission_grants = [RolePermission(permission=Permission.MACHINE_VIEW)]
        session.add(role)
        await session.flush()
        user = User(
            username=username,
            auth_provider=AuthProvider.LDAP,
            is_active=is_active,
            role_id=role.id,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user.id


async def _admin_role_id(db_session_factory: Any) -> str:
    async with db_session_factory() as session:
        from sqlalchemy import select

        role = (
            (await session.execute(select(Role).where(Role.name.like("role-for-%"))))
            .scalars()
            .first()
        )
        assert role is not None
        return str(role.id)


async def test_bulk_deactivate_users(client, db_session_factory):
    a = await _make_user(db_session_factory, username="bulk-deact-a")
    b = await _make_user(db_session_factory, username="bulk-deact-b")

    await client.get("/users")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/users/bulk/deactivate",
        data={"user_ids": [str(a), str(b)], "csrf_token": csrf_token},
    )
    assert response.status_code == 303

    async with db_session_factory() as session:
        assert (await session.get(User, a)).is_active is False
        assert (await session.get(User, b)).is_active is False


async def test_bulk_activate_users(client, db_session_factory):
    a = await _make_user(db_session_factory, username="bulk-act-a", is_active=False)

    await client.get("/users")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/users/bulk/activate", data={"user_ids": [str(a)], "csrf_token": csrf_token}
    )
    assert response.status_code == 303

    async with db_session_factory() as session:
        assert (await session.get(User, a)).is_active is True


async def test_bulk_sign_out_users(client, db_session_factory):
    from app.auth.sessions import create_session

    a = await _make_user(db_session_factory, username="bulk-signout-a")
    async with db_session_factory() as session:
        user = await session.get(User, a)
        await create_session(session, user, ip_address="1.2.3.4", user_agent="test")
        await session.commit()

    from sqlalchemy import select

    from app.db.models.user_session import UserSession

    async with db_session_factory() as session:
        before = (
            await session.execute(select(UserSession).where(UserSession.user_id == a))
        ).scalars().all()
        assert len(before) == 1

    await client.get("/users")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/users/bulk/sign-out", data={"user_ids": [str(a)], "csrf_token": csrf_token}
    )
    assert response.status_code == 303

    async with db_session_factory() as session:
        after = (
            await session.execute(select(UserSession).where(UserSession.user_id == a))
        ).scalars().all()
        assert all(s.revoked_at is not None for s in after)


async def test_bulk_set_role(client, db_session_factory):
    a = await _make_user(db_session_factory, username="bulk-role-a")
    b = await _make_user(db_session_factory, username="bulk-role-b")
    role_id = await _admin_role_id(db_session_factory)

    await client.get("/users")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/users/bulk/role",
        data={"user_ids": [str(a), str(b)], "role_id": role_id, "csrf_token": csrf_token},
    )
    assert response.status_code == 303

    async with db_session_factory() as session:
        assert str((await session.get(User, a)).role_id) == role_id
        assert str((await session.get(User, b)).role_id) == role_id


async def test_bulk_action_drops_the_acting_admins_own_id_from_the_selection(
    client, db_session_factory
):
    """The acting admin's own row is silently dropped from the batch, the
    same "never let a bulk action touch the actor's own row" rule the
    single-account routes enforce explicitly."""
    from sqlalchemy import select

    async with db_session_factory() as session:
        admin = (await session.execute(select(User))).scalars().first()
        admin_id = admin.id
        was_active = admin.is_active

    await client.get("/users")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/users/bulk/deactivate",
        data={"user_ids": [str(admin_id)], "csrf_token": csrf_token},
    )
    # Nothing left to act on once the actor's own id is dropped.
    assert response.status_code == 303
    assert "bulk_error" in response.headers["location"]
    followed = await client.get(response.headers["location"])
    assert "Select at least one other user." in followed.text

    async with db_session_factory() as session:
        assert (await session.get(User, admin_id)).is_active == was_active


async def test_bulk_deactivate_requires_csrf_token(client, db_session_factory):
    a = await _make_user(db_session_factory, username="bulk-csrf-a")

    response = await client.post("/users/bulk/deactivate", data={"user_ids": [str(a)]})

    assert response.status_code == 403


async def test_bulk_actions_require_user_manage_permission(client, login_as, db_session_factory):
    a = await _make_user(db_session_factory, username="bulk-perm-a")
    await login_as(client, permissions={Permission.MACHINE_VIEW})

    response = await client.post(
        "/users/bulk/deactivate", data={"user_ids": [str(a)], "csrf_token": "whatever"}
    )

    assert response.status_code == 403


async def _api_token(client: Any) -> dict[str, str]:
    import re

    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "bulk-test-token", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None, response.text
    return {"Authorization": f"Bearer {match.group(1)}"}


async def test_bulk_deactivate_users_via_api(client, db_session_factory):
    a = await _make_user(db_session_factory, username="api-bulk-deact-a")
    headers = await _api_token(client)

    response = await client.post(
        "/api/v1/users/bulk/deactivate", json={"user_ids": [str(a)]}, headers=headers
    )

    assert response.status_code == 200, response.text
    assert response.json() == {"deactivated": 1}
    async with db_session_factory() as session:
        assert (await session.get(User, a)).is_active is False


async def test_bulk_role_via_api_drops_the_actors_own_id(client, db_session_factory):
    from sqlalchemy import select

    headers = await _api_token(client)
    role_id = await _admin_role_id(db_session_factory)

    async with db_session_factory() as session:
        admin = (await session.execute(select(User))).scalars().first()
        admin_id = admin.id

    response = await client.post(
        "/api/v1/users/bulk/role",
        json={"user_ids": [str(admin_id)], "role_id": role_id},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.json() == {"updated": 0}  # the actor's own id was dropped
