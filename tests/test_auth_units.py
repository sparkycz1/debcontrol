"""Unit tests for pieces of app.auth that don't need a running app — LDAP
bind logic (against a mocked `ldap3.Connection`, since there's no real
directory in this environment), password hashing, and the RBAC
"MANAGE implies VIEW" rule.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import ldap3
import pytest

from app.auth import ldap as ldap_module
from app.auth.security import hash_password, verify_password
from app.db.models.app_settings import AppSettings
from app.db.models.role import Permission, Role, RolePermission
from app.db.models.user import User


def _make_app_settings(**overrides: object) -> AppSettings:
    settings = AppSettings(
        id=1,
        ldap_server_uri="ldap://dc.example.com",
        ldap_use_starttls=False,
        ldap_bind_dn="cn=service,dc=example,dc=com",
        ldap_bind_password_encrypted=None,
        ldap_user_search_base="ou=people,dc=example,dc=com",
        ldap_user_search_filter="(uid={username})",
        ldap_connect_timeout_seconds=5,
    )
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


async def test_ldap_authenticate_rejects_empty_password_without_binding():
    """An empty password must never reach ldap3's bind — many directories
    treat that as a trivially-successful "unauthenticated bind"."""
    with patch("app.auth.ldap.ldap3.Connection") as mock_connection:
        result = await ldap_module.authenticate(_make_app_settings(), "alice", "")
    assert result is False
    mock_connection.assert_not_called()


async def test_ldap_authenticate_raises_when_not_configured():
    with pytest.raises(ldap_module.LdapUnavailableError):
        await ldap_module.authenticate(_make_app_settings(ldap_server_uri=None), "alice", "secret")


async def test_ldap_authenticate_success_path(monkeypatch):
    """Search finds exactly one entry; binding as that DN with the given
    password succeeds."""

    entry = MagicMock()
    entry.entry_dn = "uid=alice,ou=people,dc=example,dc=com"

    service_conn = MagicMock()
    service_conn.bind.return_value = True
    service_conn.entries = [entry]
    service_conn.__enter__ = MagicMock(return_value=service_conn)
    service_conn.__exit__ = MagicMock(return_value=False)

    user_conn = MagicMock()
    user_conn.bind.return_value = True
    user_conn.__enter__ = MagicMock(return_value=user_conn)
    user_conn.__exit__ = MagicMock(return_value=False)

    connections = [service_conn, user_conn]

    def _fake_connection(*args, **kwargs):
        return connections.pop(0)

    monkeypatch.setattr(ldap3, "Connection", _fake_connection)
    monkeypatch.setattr(ldap3, "Server", MagicMock())

    result = await ldap_module.authenticate(_make_app_settings(), "alice", "correct-password")
    assert result is True
    user_conn.bind.assert_called_once()


async def test_ldap_authenticate_fails_when_user_not_found(monkeypatch):
    service_conn = MagicMock()
    service_conn.bind.return_value = True
    service_conn.entries = []  # nobody matched the filter
    service_conn.__enter__ = MagicMock(return_value=service_conn)
    service_conn.__exit__ = MagicMock(return_value=False)

    monkeypatch.setattr(ldap3, "Connection", MagicMock(return_value=service_conn))
    monkeypatch.setattr(ldap3, "Server", MagicMock())

    result = await ldap_module.authenticate(_make_app_settings(), "nobody", "whatever")
    assert result is False


def test_password_hash_roundtrip():
    hashed = hash_password("a-good-password-123")
    assert verify_password(hashed, "a-good-password-123") is True
    assert verify_password(hashed, "wrong-password") is False


def test_verify_password_never_raises_on_garbage_hash():
    assert verify_password("not-a-real-hash", "anything") is False


def test_machine_manage_implies_machine_view_but_not_other_permissions():
    role = Role(name="manage-only")
    role.permission_grants = [RolePermission(permission=Permission.MACHINE_MANAGE)]
    user = User(username="x", role=role)

    assert user.has_permission(Permission.MACHINE_MANAGE) is True
    assert user.has_permission(Permission.MACHINE_VIEW) is True
    assert user.has_permission(Permission.GROUP_VIEW) is False
    assert user.has_permission(Permission.ACTION_UPDATES) is False
