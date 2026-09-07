"""WebAuthn/passkeys — a second login factor alongside TOTP (see
`app.auth.webauthn`, `app.auth.middleware`'s `_totp_enrollment_required`,
and `app/web/routes/auth.py`'s `/login/webauthn/*` and
`/account/webauthn/*` routes).

The actual cryptographic ceremony (attestation/assertion signature
checking) is py_webauthn's job, not this app's — these tests don't
simulate a real authenticator. Instead they monkeypatch
`app.web.routes.auth.webauthn_module`'s verification functions with canned
results and exercise the *wiring* around them: which account a challenge
belongs to, that a stored credential is matched by id before being handed
to verification, that a failed/mismatched ceremony never creates a
session, and that the TOTP-or-passkey second-factor gate in
`app.auth.middleware` treats either as satisfying `Role.require_totp`.
"""

from __future__ import annotations

from typing import Any

from httpx import ASGITransport, AsyncClient
from webauthn.helpers.structs import (
    AttestationFormat,
    CredentialDeviceType,
    PublicKeyCredentialType,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

from app.auth import webauthn as webauthn_module
from app.auth.security import hash_password
from app.auth.sessions import SESSION_COOKIE_NAME
from app.auth.webauthn import WebAuthnError
from app.db.models.role import Permission, Role, RolePermission
from app.db.models.user import AuthProvider, User
from app.db.models.webauthn_credential import WebAuthnCredential
from app.main import app
from tests.conftest import ADMIN_USERNAME, _configure_app_for_tests, create_local_user


class _FakeAuthResult:
    def __init__(self, new_sign_count: int = 1) -> None:
        self.new_sign_count = new_sign_count


def _fake_registration(credential_id: bytes = b"cred-1") -> VerifiedRegistration:
    return VerifiedRegistration(
        credential_id=credential_id,
        credential_public_key=b"a-fake-public-key",
        sign_count=0,
        aaguid="00000000-0000-0000-0000-000000000000",
        fmt=AttestationFormat.NONE,
        credential_type=PublicKeyCredentialType.PUBLIC_KEY,
        user_verified=True,
        attestation_object=b"ao",
        credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
        credential_backed_up=False,
    )


async def _add_webauthn_credential(
    db_session_factory: Any, user_id: Any, *, credential_id: bytes = b"cred-1"
) -> WebAuthnCredential:
    async with db_session_factory() as db:
        cred = WebAuthnCredential(
            user_id=user_id,
            name="Test passkey",
            credential_id=credential_id,
            public_key=b"a-fake-public-key",
            sign_count=0,
            device_type="single_device",
            backed_up=False,
        )
        db.add(cred)
        await db.commit()
        await db.refresh(cred)
    return cred


async def _csrf(client: AsyncClient, *, warm_path: str = "/login") -> str:
    await client.get(warm_path)
    token = client.cookies.get("csrftoken")
    assert token is not None
    return token


# --- Middleware gating: a passkey satisfies Role.require_totp too --------


async def test_registered_passkey_satisfies_require_totp(db_session_factory):
    from app.auth.sessions import create_session

    _configure_app_for_tests(db_session_factory)
    async with db_session_factory() as db:
        role = Role(name="role-needs-2fa", require_totp=True)
        role.permission_grants = [RolePermission(permission=p) for p in Permission]
        db.add(role)
        await db.flush()
        user = User(
            username="has-passkey",
            auth_provider=AuthProvider.LOCAL,
            password_hash=hash_password("a-very-good-password-123"),
            is_active=True,
            role=role,
            totp_enabled=False,
        )
        db.add(user)
        await db.flush()
        _session, raw_token = await create_session(
            db, user, ip_address="testclient", user_agent="pytest"
        )
        await db.commit()
        await db.refresh(user)
    await _add_webauthn_credential(db_session_factory, user.id)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)
        # Not blocked into /account/totp/enroll — the passkey alone satisfies it.
        response = await ac.get("/machines")
        assert response.status_code == 200

    app.dependency_overrides.clear()


async def test_no_passkey_and_no_totp_still_blocks(db_session_factory):
    from app.auth.sessions import create_session

    _configure_app_for_tests(db_session_factory)
    async with db_session_factory() as db:
        role = Role(name="role-needs-2fa-2", require_totp=True)
        role.permission_grants = [RolePermission(permission=p) for p in Permission]
        db.add(role)
        await db.flush()
        user = User(
            username="no-second-factor",
            auth_provider=AuthProvider.LOCAL,
            password_hash=hash_password("a-very-good-password-123"),
            is_active=True,
            role=role,
            totp_enabled=False,
        )
        db.add(user)
        await db.flush()
        _session, raw_token = await create_session(
            db, user, ip_address="testclient", user_agent="pytest"
        )
        await db.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)
        response = await ac.get("/machines")
        assert response.status_code == 303
        assert response.headers["location"] == "/account/totp/enroll"

    app.dependency_overrides.clear()


# --- Login-time flow -------------------------------------------------------


async def test_login_offers_passkey_when_only_passkey_registered(
    anonymous_client, db_session_factory
):
    user = await create_local_user(
        db_session_factory, username="passkey-only", password="a-very-good-password-123"
    )
    await _add_webauthn_credential(db_session_factory, user.id)

    csrf_token = await _csrf(anonymous_client)
    step1 = await anonymous_client.post(
        "/login",
        data={
            "username": "passkey-only",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )
    assert step1.status_code == 303
    assert step1.headers["location"].startswith("/login/totp")
    assert "session" not in anonymous_client.cookies

    challenge_page = await anonymous_client.get("/login/totp")
    assert challenge_page.status_code == 200
    # No TOTP code form (never enrolled), but the passkey option is offered.
    assert 'name="code"' not in challenge_page.text
    assert "data-webauthn-login-button" in challenge_page.text


async def test_login_webauthn_verify_succeeds_with_matching_credential(
    anonymous_client, db_session_factory, monkeypatch
):
    user = await create_local_user(
        db_session_factory, username="passkey-login", password="a-very-good-password-123"
    )
    await _add_webauthn_credential(db_session_factory, user.id, credential_id=b"the-real-cred")

    monkeypatch.setattr(
        webauthn_module,
        "credential_id_from_authentication_json",
        lambda credential: b"the-real-cred",
    )
    monkeypatch.setattr(
        webauthn_module,
        "verify_authentication",
        lambda **kwargs: _FakeAuthResult(new_sign_count=7),
    )

    csrf_token = await _csrf(anonymous_client)
    await anonymous_client.post(
        "/login",
        data={
            "username": "passkey-login",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )
    assert "session" not in anonymous_client.cookies

    # Simulate the browser having fetched options (issuing the challenge
    # cookie) before completing the ceremony.
    options_response = await anonymous_client.get("/login/webauthn/options")
    assert options_response.status_code == 200
    assert "webauthn_challenge" in anonymous_client.cookies

    csrf_token = anonymous_client.cookies.get("csrftoken")
    verify_response = await anonymous_client.post(
        "/login/webauthn/verify",
        data={"credential": "{}", "csrf_token": csrf_token},
    )
    assert verify_response.status_code == 303
    assert "session" in anonymous_client.cookies

    # Sign count was updated from the verified result.
    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(
            select(WebAuthnCredential).where(WebAuthnCredential.credential_id == b"the-real-cred")
        )
        cred = result.scalar_one()
        assert cred.sign_count == 7
        assert cred.last_used_at is not None


async def test_login_webauthn_verify_rejects_unknown_credential(
    anonymous_client, db_session_factory, monkeypatch
):
    user = await create_local_user(
        db_session_factory, username="passkey-mismatch", password="a-very-good-password-123"
    )
    await _add_webauthn_credential(db_session_factory, user.id, credential_id=b"registered-cred")

    monkeypatch.setattr(
        webauthn_module,
        "credential_id_from_authentication_json",
        lambda credential: b"some-other-credential-entirely",
    )

    csrf_token = await _csrf(anonymous_client)
    await anonymous_client.post(
        "/login",
        data={
            "username": "passkey-mismatch",
            "password": "a-very-good-password-123",
            "csrf_token": csrf_token,
        },
    )
    await anonymous_client.get("/login/webauthn/options")
    csrf_token = anonymous_client.cookies.get("csrftoken")

    response = await anonymous_client.post(
        "/login/webauthn/verify", data={"credential": "{}", "csrf_token": csrf_token}
    )
    assert response.status_code == 401
    assert "session" not in anonymous_client.cookies


async def test_login_webauthn_options_requires_pending_login(anonymous_client):
    response = await anonymous_client.get("/login/webauthn/options")
    assert response.status_code == 400


# --- Two-step login: passkey as a full first-factor replacement, not ------
# --- only a second factor after a password ---------------------------------


async def test_get_login_has_no_password_field(anonymous_client):
    """Step one is username-only — see auth/login.html; the password field
    (and the passkey option) only appear on step two, /login/password."""
    response = await anonymous_client.get("/login")
    assert response.status_code == 200
    assert 'name="username"' in response.text
    assert 'name="password"' not in response.text


async def test_login_password_screen_offers_passkey_and_password(anonymous_client):
    response = await anonymous_client.get("/login/password", params={"username": "anyone"})
    assert response.status_code == 200
    assert "data-webauthn-login-button" in response.text
    assert 'name="password"' in response.text


async def test_login_password_without_a_username_redirects_to_login(anonymous_client):
    response = await anonymous_client.get(
        "/login/password", follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_passwordless_webauthn_login_succeeds_without_a_password(
    anonymous_client, db_session_factory, monkeypatch
):
    """The whole point of the two-step login: a passkey signs an account
    in directly from /login/password, no password ever submitted."""
    user = await create_local_user(
        db_session_factory, username="passwordless", password="a-very-good-password-123"
    )
    await _add_webauthn_credential(db_session_factory, user.id, credential_id=b"passwordless-cred")

    monkeypatch.setattr(
        webauthn_module,
        "credential_id_from_authentication_json",
        lambda credential: b"passwordless-cred",
    )
    monkeypatch.setattr(
        webauthn_module, "verify_authentication", lambda **kwargs: _FakeAuthResult(new_sign_count=3)
    )

    await anonymous_client.get("/login/password", params={"username": "passwordless"})

    options_response = await anonymous_client.get(
        "/login/webauthn/options", params={"username": "passwordless"}
    )
    assert options_response.status_code == 200
    assert "webauthn_challenge" in anonymous_client.cookies
    # No pending_totp cookie at any point — this never went through
    # password/LDAP verification at all.
    assert "totp_pending" not in anonymous_client.cookies

    csrf_token = anonymous_client.cookies.get("csrftoken")
    verify_response = await anonymous_client.post(
        "/login/webauthn/verify",
        data={"credential": "{}", "username": "passwordless", "csrf_token": csrf_token},
    )
    assert verify_response.status_code == 303
    assert verify_response.headers["location"] == "/"
    assert "session" in anonymous_client.cookies


async def test_login_webauthn_options_gives_the_same_error_for_unknown_username(
    anonymous_client,
):
    """Enumeration-resistance: a nonexistent account and a real one with no
    passkey get an identical response — see
    _resolve_webauthn_login_user's own docstring."""
    response = await anonymous_client.get(
        "/login/webauthn/options", params={"username": "no-such-account"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "No passkeys are registered for this account."


async def test_failed_passwordless_webauthn_login_shows_password_screen_again(
    anonymous_client, db_session_factory, monkeypatch
):
    user = await create_local_user(
        db_session_factory, username="passwordless-fail", password="a-very-good-password-123"
    )
    await _add_webauthn_credential(db_session_factory, user.id, credential_id=b"registered")

    monkeypatch.setattr(
        webauthn_module,
        "credential_id_from_authentication_json",
        lambda credential: b"some-other-credential",
    )

    await anonymous_client.get("/login/password", params={"username": "passwordless-fail"})
    await anonymous_client.get("/login/webauthn/options", params={"username": "passwordless-fail"})
    csrf_token = anonymous_client.cookies.get("csrftoken")

    response = await anonymous_client.post(
        "/login/webauthn/verify",
        data={"credential": "{}", "username": "passwordless-fail", "csrf_token": csrf_token},
    )
    assert response.status_code == 401
    assert "session" not in anonymous_client.cookies
    # Falls back to the password screen (not the post-password TOTP one —
    # this account never got that far) with the failure surfaced there.
    assert "Passkey sign-in failed." in response.text
    assert 'name="password"' in response.text


# --- Account management ----------------------------------------------------


async def test_webauthn_register_verify_creates_credential(client, monkeypatch):
    monkeypatch.setattr(
        webauthn_module,
        "verify_registration",
        lambda **kwargs: _fake_registration(credential_id=b"new-cred-id"),
    )

    options_response = await client.get("/account/webauthn/register/options")
    assert options_response.status_code == 200
    assert "webauthn_challenge" in client.cookies

    csrf_token = client.cookies.get("csrftoken")
    if not csrf_token:
        await client.get("/account")
        csrf_token = client.cookies.get("csrftoken")

    verify_response = await client.post(
        "/account/webauthn/register/verify",
        data={"credential": "{}", "name": "My YubiKey", "csrf_token": csrf_token},
    )
    assert verify_response.status_code == 200
    assert "My YubiKey" in verify_response.text


async def test_webauthn_register_verify_rejects_expired_challenge(client, monkeypatch):
    monkeypatch.setattr(
        webauthn_module,
        "verify_registration",
        lambda **kwargs: _fake_registration(),
    )
    csrf_token = client.cookies.get("csrftoken")
    if not csrf_token:
        await client.get("/account")
        csrf_token = client.cookies.get("csrftoken")

    # No prior GET .../options call — no challenge cookie was ever set.
    response = await client.post(
        "/account/webauthn/register/verify",
        data={"credential": "{}", "name": "Orphan", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "expired" in response.text.lower()


async def test_webauthn_register_verify_surfaces_verification_error(client, monkeypatch):
    def _raise(**kwargs: Any) -> Any:
        raise WebAuthnError("Passkey registration failed: bad signature")

    monkeypatch.setattr(webauthn_module, "verify_registration", _raise)

    await client.get("/account/webauthn/register/options")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/webauthn/register/verify",
        data={"credential": "{}", "name": "Bad", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "bad signature" in response.text.lower()


async def test_webauthn_delete_only_removes_own_credential(
    client, db_session_factory
):
    from sqlalchemy import select

    async with db_session_factory() as db:
        result = await db.execute(select(User).where(User.username == ADMIN_USERNAME))
        admin = result.scalar_one()
    own_cred = await _add_webauthn_credential(db_session_factory, admin.id, credential_id=b"own")

    other_user = await create_local_user(
        db_session_factory, username="someone-else", password="a-very-good-password-123"
    )
    other_cred = await _add_webauthn_credential(
        db_session_factory, other_user.id, credential_id=b"someone-elses"
    )

    csrf_token = client.cookies.get("csrftoken")
    if not csrf_token:
        await client.get("/account")
        csrf_token = client.cookies.get("csrftoken")

    # Deleting someone else's credential id is a silent no-op, not a leak.
    response = await client.post(
        f"/account/webauthn/{other_cred.id}/delete", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        assert await db.get(WebAuthnCredential, other_cred.id) is not None

    response = await client.post(
        f"/account/webauthn/{own_cred.id}/delete", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        assert await db.get(WebAuthnCredential, own_cred.id) is None
