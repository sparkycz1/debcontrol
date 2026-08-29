from __future__ import annotations

import pyotp
from httpx import AsyncClient

from app.auth.security import USERNAME_PATTERN
from tests.conftest import create_local_user


async def _csrf(client: AsyncClient) -> str:
    """Every anonymous request already gets a csrftoken cookie from
    `app.auth.middleware` — a plain GET to any page (even one that
    redirects) is enough to have one to read back."""
    await client.get("/login")
    token = client.cookies.get("csrftoken")
    assert token is not None
    return token


async def test_anonymous_request_redirects_to_login(anonymous_client):
    response = await anonymous_client.get("/machines")
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=%2Fmachines"


async def test_login_page_renders_for_anonymous_user(anonymous_client):
    response = await anonymous_client.get("/login")
    assert response.status_code == 200
    assert "<form" in response.text
    assert 'name="username"' in response.text


async def test_login_with_correct_password_succeeds(anonymous_client, db_session_factory):
    await create_local_user(
        db_session_factory, username="alice", password="a-very-good-password-123"
    )
    csrf_token = await _csrf(anonymous_client)

    response = await anonymous_client.post(
        "/login",
        data={
            "username": "alice",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert "session" in anonymous_client.cookies

    # No specific permission needed for "My account" — just being logged in.
    account = await anonymous_client.get("/account")
    assert account.status_code == 200


async def test_login_with_wrong_password_fails_generically(anonymous_client, db_session_factory):
    await create_local_user(db_session_factory, username="bob", password="a-very-good-password-123")
    csrf_token = await _csrf(anonymous_client)

    response = await anonymous_client.post(
        "/login", data={"username": "bob", "password": "wrong", "csrf_token": csrf_token}
    )
    assert response.status_code == 401
    assert "Invalid username or password" in response.text
    assert "session" not in anonymous_client.cookies


async def test_login_with_unknown_username_fails_with_the_same_message(anonymous_client):
    csrf_token = await _csrf(anonymous_client)
    response = await anonymous_client.post(
        "/login",
        data={
            "username": "nobody-like-this-exists",
            "password": "whatever",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 401
    assert "Invalid username or password" in response.text


async def test_repeated_failed_logins_lock_the_account(anonymous_client, db_session_factory):
    await create_local_user(
        db_session_factory, username="carol", password="a-very-good-password-123"
    )

    for _ in range(5):
        csrf_token = await _csrf(anonymous_client)
        await anonymous_client.post(
            "/login", data={"username": "carol", "password": "wrong", "csrf_token": csrf_token}
        )

    # Even the *correct* password is now rejected — the account is locked.
    csrf_token = await _csrf(anonymous_client)
    response = await anonymous_client.post(
        "/login",
        data={
            "username": "carol",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 429
    assert "Too many failed attempts" in response.text


async def test_logout_clears_the_session(anonymous_client, db_session_factory):
    await create_local_user(
        db_session_factory, username="dave", password="a-very-good-password-123"
    )
    csrf_token = await _csrf(anonymous_client)
    await anonymous_client.post(
        "/login",
        data={"username": "dave", "password": "a-very-good-password-123", "csrf_token": csrf_token},
    )
    assert (await anonymous_client.get("/account")).status_code == 200

    csrf_token = anonymous_client.cookies.get("csrftoken")
    logout = await anonymous_client.post("/logout", data={"csrf_token": csrf_token})
    assert logout.status_code == 303
    assert logout.headers["location"] == "/login"

    again = await anonymous_client.get("/account")
    assert again.status_code == 303


async def test_must_change_password_redirects_to_account(anonymous_client, db_session_factory):
    await create_local_user(
        db_session_factory,
        username="erin",
        password="a-very-good-password-123",
        must_change_password=True,
    )
    csrf_token = await _csrf(anonymous_client)
    response = await anonymous_client.post(
        "/login",
        data={"username": "erin", "password": "a-very-good-password-123", "csrf_token": csrf_token},
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/account"


async def test_totp_enrollment_and_login_flow(anonymous_client, db_session_factory):
    await create_local_user(
        db_session_factory, username="frank", password="a-very-good-password-123"
    )
    csrf_token = await _csrf(anonymous_client)
    await anonymous_client.post(
        "/login",
        data={
            "username": "frank",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )

    enroll_form = await anonymous_client.get("/account/totp/enroll")
    assert enroll_form.status_code == 200
    secret = enroll_form.text.split('name="secret" value="')[1].split('"')[0]
    csrf_token = anonymous_client.cookies.get("csrftoken")

    confirm = await anonymous_client.post(
        "/account/totp/enroll",
        data={"secret": secret, "code": pyotp.TOTP(secret).now(), "csrf_token": csrf_token},
    )
    assert confirm.status_code == 200
    assert "Save these recovery codes" in confirm.text

    # Log out, then log back in — this time a second, TOTP step is required.
    csrf_token = anonymous_client.cookies.get("csrftoken")
    await anonymous_client.post("/logout", data={"csrf_token": csrf_token})

    csrf_token = await _csrf(anonymous_client)
    step1 = await anonymous_client.post(
        "/login",
        data={
            "username": "frank",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )
    assert step1.status_code == 303
    assert step1.headers["location"].startswith("/login/totp")
    assert "session" not in anonymous_client.cookies

    csrf_token = anonymous_client.cookies.get("csrftoken")
    step2 = await anonymous_client.post(
        "/login/totp", data={"code": pyotp.TOTP(secret).now(), "csrf_token": csrf_token}
    )
    assert step2.status_code == 303
    assert "session" in anonymous_client.cookies


async def test_wrong_totp_code_is_rejected(anonymous_client, db_session_factory):
    await create_local_user(
        db_session_factory, username="grace", password="a-very-good-password-123"
    )
    csrf_token = await _csrf(anonymous_client)
    await anonymous_client.post(
        "/login",
        data={
            "username": "grace",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )
    enroll_form = await anonymous_client.get("/account/totp/enroll")
    secret = enroll_form.text.split('name="secret" value="')[1].split('"')[0]
    csrf_token = anonymous_client.cookies.get("csrftoken")
    await anonymous_client.post(
        "/account/totp/enroll",
        data={"secret": secret, "code": pyotp.TOTP(secret).now(), "csrf_token": csrf_token},
    )
    csrf_token = anonymous_client.cookies.get("csrftoken")
    await anonymous_client.post("/logout", data={"csrf_token": csrf_token})

    csrf_token = await _csrf(anonymous_client)
    await anonymous_client.post(
        "/login",
        data={
            "username": "grace",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )
    csrf_token = anonymous_client.cookies.get("csrftoken")
    response = await anonymous_client.post(
        "/login/totp", data={"code": "000000", "csrf_token": csrf_token}
    )
    assert response.status_code == 401
    assert "Invalid code" in response.text


def test_username_pattern_rejects_uppercase_and_spaces():
    assert USERNAME_PATTERN.match("valid.user-99")
    assert not USERNAME_PATTERN.match("Invalid User")
    assert not USERNAME_PATTERN.match("ab")  # too short


async def test_csrf_rejection_is_audit_logged(anonymous_client, db_session_factory):
    from sqlalchemy import select

    from app.db.models.audit_log import AuditLogEntry, AuditOutcome

    await anonymous_client.get("/login")  # provisions the csrftoken cookie
    response = await anonymous_client.post(
        "/login",
        data={"username": "nobody", "password": "wrong", "csrf_token": "not-the-cookie-value"},
    )
    assert response.status_code == 403

    async with db_session_factory() as session:
        result = await session.execute(
            select(AuditLogEntry).where(AuditLogEntry.action == "auth.csrf_rejected")
        )
        entry = result.scalar_one()
    assert entry.outcome == AuditOutcome.DENIED
    assert "/login" in entry.summary


async def test_login_is_rate_limited_per_ip_after_many_attempts(anonymous_client):
    from app.web.routes.auth import _LOGIN_RATE_LIMIT

    csrf_token = await _csrf(anonymous_client)
    for _ in range(_LOGIN_RATE_LIMIT):
        response = await anonymous_client.post(
            "/login",
            data={"username": "nobody", "password": "wrong", "csrf_token": csrf_token},
        )
        assert response.status_code == 401

    response = await anonymous_client.post(
        "/login",
        data={"username": "nobody", "password": "wrong", "csrf_token": csrf_token},
    )
    assert response.status_code == 429
    assert "Too many attempts" in response.text
