from __future__ import annotations

import re
from typing import Any

from httpx import AsyncClient

from app.auth.sessions import IMPERSONATION_RETURN_COOKIE_NAME, SESSION_COOKIE_NAME, create_session
from app.db.models.role import Permission, Role, RolePermission
from app.db.models.user import AuthProvider, User


async def _csrf(client: AsyncClient) -> str:
    await client.get("/dashboard")
    token = client.cookies.get("csrftoken")
    assert token is not None
    return token


async def _make_user(
    db_session_factory: Any, *, username: str, permissions: set[Permission], **kw: Any
) -> tuple[User, str]:
    async with db_session_factory() as db:
        role = Role(name=f"role-{username}")
        role.permission_grants = [RolePermission(permission=p) for p in permissions]
        db.add(role)
        await db.flush()
        user = User(username=username, auth_provider=AuthProvider.LDAP, role=role, **kw)
        db.add(user)
        await db.commit()
        await db.refresh(user)

        _, raw_token = await create_session(db, user, ip_address=None, user_agent=None)
    return user, raw_token


async def test_admin_can_impersonate_and_stop_returns_to_own_account(client, db_session_factory):
    target, _target_token = await _make_user(
        db_session_factory, username="target-user", permissions={Permission.MACHINE_VIEW}
    )

    csrf_token = await _csrf(client)
    response = await client.post(
        f"/users/{target.id}/impersonate", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert client.cookies.get(IMPERSONATION_RETURN_COOKIE_NAME) is not None

    # Now acting as the target — the topbar shows their name.
    account_page = await client.get("/account")
    assert account_page.status_code == 200
    assert "target-user" in account_page.text

    # "Logging out" while impersonating returns to the admin, not the login page.
    logout_csrf = client.cookies.get("csrftoken")
    stop = await client.post("/logout", data={"csrf_token": logout_csrf})
    assert stop.status_code == 303
    assert stop.headers["location"] == "/users"
    assert client.cookies.get(IMPERSONATION_RETURN_COOKIE_NAME) is None

    whoami = await client.get("/account")
    assert whoami.status_code == 200
    assert "test-admin" in whoami.text


async def test_impersonation_requires_permission(client, login_as):
    target = await login_as(
        client, permissions={Permission.MACHINE_VIEW}, username="not-an-admin"
    )
    csrf_token = await _csrf(client)
    response = await client.post(
        f"/users/{target.id}/impersonate", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 403


async def test_cannot_impersonate_self(client):

    from tests.conftest import ADMIN_USERNAME

    # The `client` fixture's own id isn't directly exposed — resolve it via
    # the users list page, which links to /users/{id}/edit for every account.
    users_page = await client.get("/users")
    row = next(r for r in users_page.text.split("<tr>") if f">{ADMIN_USERNAME}<" in r)
    match = re.search(r"/users/([0-9a-f-]{36})/edit", row)
    assert match is not None, row
    self_id = match.group(1)

    csrf_token = await _csrf(client)
    response = await client.post(f"/users/{self_id}/impersonate", data={"csrf_token": csrf_token})
    assert response.status_code == 400


async def test_cannot_impersonate_an_account_that_can_itself_impersonate(
    client, db_session_factory
):
    other_admin, _ = await _make_user(
        db_session_factory, username="other-admin", permissions={Permission.USER_IMPERSONATE}
    )
    csrf_token = await _csrf(client)
    response = await client.post(
        f"/users/{other_admin.id}/impersonate", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 400
    assert "impersonate others" in response.text


async def test_cannot_impersonate_disabled_account(client, db_session_factory):
    target, _ = await _make_user(
        db_session_factory,
        username="disabled-target",
        permissions={Permission.MACHINE_VIEW},
        is_active=False,
    )
    csrf_token = await _csrf(client)
    response = await client.post(
        f"/users/{target.id}/impersonate", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 400


async def test_impersonation_is_audit_logged(client, db_session_factory):
    target, _ = await _make_user(
        db_session_factory, username="audited-target", permissions={Permission.MACHINE_VIEW}
    )
    csrf_token = await _csrf(client)
    await client.post(f"/users/{target.id}/impersonate", data={"csrf_token": csrf_token})
    logout_csrf = client.cookies.get("csrftoken")
    await client.post("/logout", data={"csrf_token": logout_csrf})

    # Log back in as an admin (full permissions) to read the audit log.
    admin2, admin2_token = await _make_user(
        db_session_factory, username="audit-reader", permissions=set(Permission)
    )
    client.cookies.set(SESSION_COOKIE_NAME, admin2_token)
    audit_page = await client.get("/audit")
    assert "user.impersonate.start" in audit_page.text
    assert "user.impersonate.stop" in audit_page.text


def _has_nested_form(html: str) -> bool:
    """True if any `<form>` element in `html` contains another `<form>`
    start tag before its own closing `</form>` — invalid HTML a browser
    silently "fixes" by dropping the inner start tag, which then makes
    the inner form's own controls (its action, its hidden CSRF input)
    belong to the *outer* form instead. A real regression this way once
    made the per-row "Impersonate" button on /users silently submit to
    POST /users (the create-user endpoint, whose action-less outer
    <form> wraps the whole table) instead of its own
    `/users/{id}/impersonate` — see users/list.html's own comment on the
    fix. Deliberately not a full HTML parser: just enough to catch this
    exact class of nesting bug in any page's markup, without adding a new
    dependency for it."""
    depth = 0
    for match in re.finditer(r"<(/?)form\b", html):
        if match.group(1):
            depth -= 1
        else:
            if depth > 0:
                return True
            depth += 1
    return False


async def test_users_list_has_no_nested_forms(client, db_session_factory):
    """Regression test for the exact bug above: render /users with an
    impersonatable target present (the per-row form only renders at all
    once one exists — see users/list.html) and check the whole page for
    any <form> nested inside another."""

    await _make_user(
        db_session_factory, username="impersonatable", permissions={Permission.MACHINE_VIEW}
    )

    users_page = await client.get("/users")
    # A missing i18n key would mean the button never renders at all — a
    # different bug, checked here so this test fails loudly rather than
    # silently passing by finding nothing to check.
    assert "users.impersonate" not in users_page.text
    assert not _has_nested_form(users_page.text), users_page.text


async def test_impersonate_button_posts_to_its_own_url_not_the_page_url(
    client, db_session_factory
):
    """The rendered per-row form's own `action` must be
    `/users/{id}/impersonate`, distinct from the page's own `/users` URL a
    nested-form bug would have silently redirected it to (see the test
    above and users/list.html's own comment)."""

    target, _ = await _make_user(
        db_session_factory, username="impersonate-target", permissions={Permission.MACHINE_VIEW}
    )

    users_page = await client.get("/users")
    row = next(r for r in users_page.text.split("<tr>") if f">{target.username}<" in r)
    match = re.search(r'action="(/users/[0-9a-f-]{36}/impersonate)"', row)
    assert match is not None, row
    assert match.group(1) == f"/users/{target.id}/impersonate"
