"""Self-service email on `/account` — `POST /account/display-name` also
persists `User.email` now (same route, since it's the same "profile"
form) — see `app/web/routes/auth.py`'s `update_display_name`."""

from __future__ import annotations

from app.db.models.role import Role
from app.db.models.user import AuthProvider, User


async def test_user_can_set_their_own_email(client, db_session_factory):
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/account/display-name",
        data={
            "display_name": "Admin",
            "email": "  ADMIN@Example.com  ",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303

    account_page = await client.get("/account")
    assert "admin@example.com" in account_page.text


async def test_user_rejects_malformed_own_email(client):
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/account/display-name",
        data={"display_name": "", "email": "not-an-email", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "look like" in response.text


async def test_user_cannot_take_an_email_already_in_use(client, db_session_factory):
    async with db_session_factory() as db:
        role = Role(name="role-other-account")
        db.add(role)
        await db.flush()
        db.add(
            User(
                username="other-account",
                auth_provider=AuthProvider.LDAP,
                email="taken@example.com",
                role=role,
            )
        )
        await db.commit()

    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/account/display-name",
        data={"display_name": "", "email": "taken@example.com", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "already in use" in response.text
