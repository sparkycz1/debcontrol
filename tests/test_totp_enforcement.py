"""Role-enforced TOTP (`Role.require_totp`) — real-time, app-wide enforcement
in `app.auth.middleware` (session requests) and
`app.auth.dependencies.get_api_token_user` (API-token requests). See those
modules' docstrings for the design.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import pyotp
from httpx2 import ASGITransport, AsyncClient

from app.auth.api_tokens import create_api_token
from app.auth.security import hash_password
from app.auth.sessions import SESSION_COOKIE_NAME, create_session
from app.core.security import encrypt_secret
from app.db.models.role import Permission, Role, RolePermission
from app.db.models.user import AuthProvider, User
from app.main import app
from tests.conftest import _configure_app_for_tests


async def _make_user_with_role(
    db_session_factory: Any,
    *,
    username: str,
    require_totp: bool,
    totp_enabled: bool = False,
    auth_provider: AuthProvider = AuthProvider.LOCAL,
) -> tuple[User, str]:
    async with db_session_factory() as db:
        role = Role(name=f"role-for-{username}", require_totp=require_totp)
        role.permission_grants = [RolePermission(permission=p) for p in Permission]
        db.add(role)
        await db.flush()

        totp_secret = pyotp.random_base32()
        user = User(
            username=username,
            auth_provider=auth_provider,
            password_hash=hash_password("a-very-good-password-123")
            if auth_provider == AuthProvider.LOCAL
            else None,
            is_active=True,
            role=role,
            totp_enabled=totp_enabled,
            totp_secret_encrypted=encrypt_secret(totp_secret) if totp_enabled else None,
            totp_confirmed_at=datetime.now(UTC) if totp_enabled else None,
        )
        db.add(user)
        await db.flush()

        _session, raw_token = await create_session(
            db, user, ip_address="testclient", user_agent="pytest"
        )
        await db.commit()
        await db.refresh(user)
    return user, raw_token


async def test_role_require_totp_blocks_non_enrolled_user(db_session_factory):
    _configure_app_for_tests(db_session_factory)
    _user, raw_token = await _make_user_with_role(
        db_session_factory, username="needs-totp", require_totp=True, totp_enabled=False
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)

        blocked = await ac.get("/machines")
        assert blocked.status_code == 303
        assert blocked.headers["location"] == "/account/totp/enroll"

        # Enrollment itself, and the account page it's linked from, stay reachable.
        enroll_page = await ac.get("/account/totp/enroll")
        assert enroll_page.status_code == 200
        assert "Your role requires two-factor authentication" in enroll_page.text

        account_page = await ac.get("/account")
        assert account_page.status_code == 200

    app.dependency_overrides.clear()


async def test_logout_stays_reachable_while_totp_enrollment_is_blocked(db_session_factory):
    """A user blocked pending TOTP enrollment must still be able to end their
    own session — not be trapped on the enrollment page with no way out."""
    _configure_app_for_tests(db_session_factory)
    _user, raw_token = await _make_user_with_role(
        db_session_factory, username="wants-to-leave", require_totp=True, totp_enabled=False
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)

        csrf_token = ac.cookies.get("csrftoken")
        if not csrf_token:
            await ac.get("/account")
            csrf_token = ac.cookies.get("csrftoken")

        logout = await ac.post("/logout", data={"csrf_token": csrf_token})
        assert logout.status_code == 303
        assert logout.headers["location"] == "/login"

    app.dependency_overrides.clear()


async def test_enrolling_totp_lifts_the_block_without_re_login(db_session_factory):
    _configure_app_for_tests(db_session_factory)
    _user, raw_token = await _make_user_with_role(
        db_session_factory, username="enrolls-now", require_totp=True, totp_enabled=False
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)

        blocked = await ac.get("/machines")
        assert blocked.status_code == 303

        enroll_page = await ac.get("/account/totp/enroll")
        csrf_token = ac.cookies.get("csrftoken")
        assert csrf_token is not None

        # Extract the freshly generated secret from the rendered page.
        match = re.search(r"<code>([A-Z2-7]+)</code>", enroll_page.text)
        assert match is not None
        secret = match.group(1)
        code = pyotp.TOTP(secret).now()

        confirm = await ac.post(
            "/account/totp/enroll",
            data={"csrf_token": csrf_token, "secret": secret, "code": code},
        )
        assert confirm.status_code == 200

        # No re-login needed — the same session can now reach other pages.
        after = await ac.get("/machines")
        assert after.status_code == 200

    app.dependency_overrides.clear()


async def test_toggling_role_flag_on_blocks_on_next_request(db_session_factory):
    _configure_app_for_tests(db_session_factory)
    user, raw_token = await _make_user_with_role(
        db_session_factory, username="already-logged-in", require_totp=False, totp_enabled=False
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)

        ok = await ac.get("/machines")
        assert ok.status_code == 200

        # An admin flips the role's require_totp flag on, mid-session.
        async with db_session_factory() as db:
            role = await db.get(Role, user.role_id)
            assert role is not None
            role.require_totp = True
            await db.commit()

        blocked = await ac.get("/machines")
        assert blocked.status_code == 303
        assert blocked.headers["location"] == "/account/totp/enroll"

    app.dependency_overrides.clear()


async def test_oidc_accounts_are_exempt_from_require_totp(db_session_factory):
    _configure_app_for_tests(db_session_factory)
    _user, raw_token = await _make_user_with_role(
        db_session_factory,
        username="oidc-user",
        require_totp=True,
        totp_enabled=False,
        auth_provider=AuthProvider.OIDC,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)
        response = await ac.get("/machines")
        assert response.status_code == 200

    app.dependency_overrides.clear()


async def test_api_token_request_gets_403_when_role_requires_totp(db_session_factory):
    _configure_app_for_tests(db_session_factory)
    async with db_session_factory() as db:
        role = Role(name="api-role", require_totp=True)
        role.permission_grants = [RolePermission(permission=p) for p in Permission]
        db.add(role)
        await db.flush()
        user = User(
            username="api-needs-totp",
            auth_provider=AuthProvider.LOCAL,
            password_hash=hash_password("a-very-good-password-123"),
            is_active=True,
            role=role,
            api_access_enabled=True,
        )
        db.add(user)
        await db.flush()
        _token, raw_token = await create_api_token(db, user, name="ci", expires_at=None)
        await db.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        response = await ac.get(
            "/api/v1/machines", headers={"Authorization": f"Bearer {raw_token}"}
        )
        assert response.status_code == 403
        assert "two-factor" in response.json()["detail"]

    app.dependency_overrides.clear()
