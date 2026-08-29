from __future__ import annotations

import re

from sqlalchemy import select

from app.db.models.role import Permission, Role
from app.db.models.user import User
from tests.conftest import ADMIN_USERNAME


def _extract_user_edit_link(users_page_html: str) -> str:
    """Only ever called when exactly one user (the one seeded by the
    `client` fixture) exists yet, so "the only edit link on the page" and
    "that user's edit link" are the same thing."""
    match = re.search(r"/users/([0-9a-f-]{36})/edit", users_page_html)
    assert match is not None, users_page_html
    return match.group(1)


async def test_no_permissions_gets_403_on_a_view_page(client, login_as):
    await login_as(client, permissions=frozenset())
    response = await client.get("/machines")
    assert response.status_code == 403


async def test_view_only_permission_allows_get_but_not_post(client, login_as):
    await login_as(client, permissions={Permission.MACHINE_VIEW})
    assert (await client.get("/machines")).status_code == 200

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/machines",
        data={
            "name": "nope",
            "ip_address": "10.0.0.1",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 403


async def test_manage_permission_implies_view(client, login_as):
    """Granting MACHINE_MANAGE alone must still allow reaching the (view-gated)
    machines list — see app/db/models/user.py's `_MANAGE_IMPLIES_VIEW`."""
    await login_as(client, permissions={Permission.MACHINE_MANAGE})
    assert (await client.get("/machines")).status_code == 200


async def test_action_permission_is_independent_of_manage(client, login_as):
    """`action.updates`/`action.power` are their own permissions — having
    `machine.manage` doesn't automatically grant them."""
    await login_as(client, permissions={Permission.MACHINE_MANAGE, Permission.MACHINE_VIEW})

    machines_page = await client.get("/machines")
    assert machines_page.status_code == 200

    # Create a machine (allowed — machine.manage), then try to trigger
    # updates on it (should be denied — no action.updates).
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    create = await client.post(
        "/machines",
        data={
            "name": "rbac-test",
            "ip_address": "10.0.0.2",
            "port": "22",
            "username": "admin",
            "auth_method": "ssh_key",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    assert create.status_code == 303
    machine_id = create.headers["location"].rsplit("/", 1)[-1]

    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/machines/{machine_id}/check-updates", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 403


async def test_user_manage_gates_the_users_and_roles_pages(client, login_as):
    await login_as(client, permissions=frozenset())
    assert (await client.get("/users")).status_code == 403
    assert (await client.get("/roles")).status_code == 403

    await login_as(client, permissions={Permission.USER_MANAGE}, username="user-admin")
    assert (await client.get("/users")).status_code == 200
    assert (await client.get("/roles")).status_code == 200


async def test_nav_only_shows_permitted_links(client, login_as):
    await login_as(client, permissions={Permission.AUDIT_VIEW})
    page = await client.get("/audit")
    assert page.status_code == 200
    assert 'href="/audit"' in page.text
    # The brand link in the header always points at /machines regardless of
    # permission (a 403 there is harmless) — what must NOT appear is the
    # actual nav *link* to it.
    assert '<a href="/machines">Machines</a>' not in page.text
    assert '<a href="/users">Users</a>' not in page.text


async def test_cannot_delete_own_account(client):
    users_page = await client.get("/users")
    self_id = _extract_user_edit_link(users_page.text)

    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(f"/users/{self_id}/delete", data={"csrf_token": csrf_token})
    assert response.status_code == 403


async def test_cannot_deactivate_own_account(client, db_session_factory):
    users_page = await client.get("/users")
    self_id = _extract_user_edit_link(users_page.text)

    async with db_session_factory() as db:
        result = await db.execute(select(User).where(User.username == ADMIN_USERNAME))
        own_role_id = result.scalar_one().role_id

    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/users/{self_id}/edit",
        data={
            "username": ADMIN_USERNAME,
            "display_name": "",
            "auth_provider": "local",
            "password": "",
            "role_id": str(own_role_id),
            # is_active omitted — an unchecked checkbox.
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 403
    assert "own account" in response.text


async def test_removing_user_manage_from_the_only_admin_role_is_blocked(client, db_session_factory):
    """The acting admin's own role is the only one granting `user.manage` —
    editing it to drop that permission would leave nobody able to manage
    users, including the person making the change."""
    async with db_session_factory() as db:
        result = await db.execute(select(Role))
        admin_role = result.scalars().one()  # the `client` fixture creates exactly one role

    edit_page = await client.get(f"/roles/{admin_role.id}/edit")
    assert edit_page.status_code == 200

    csrf_token = client.cookies.get("csrftoken")
    remaining_permissions = [p.value for p in Permission if p != Permission.USER_MANAGE]
    response = await client.post(
        f"/roles/{admin_role.id}/edit",
        data={
            "name": admin_role.name,
            "description": "",
            "permissions": remaining_permissions,
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 409
    assert "no other active account" in response.text
