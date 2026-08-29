"""The `/login` form's actual logic: look up the account, branch to local
password verification or an LDAP bind depending on `User.auth_provider`, and
the shared brute-force lockout bookkeeping used by *both* that step and the
TOTP step that can follow it.

Deliberately returns a generic "invalid_credentials" reason for a
nonexistent username, a wrong password, an inactive account, and an OIDC
account trying to use the password form — the route shows the same message
for all of them, so none of that is distinguishable from the outside
(username enumeration). A locked-out account gets its own distinct message
instead — hiding that from a legitimate locked-out user is worse than the
marginal information it'd otherwise give an attacker who already knows they
triggered it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import totp as totp_module
from app.auth.ldap import LdapUnavailableError
from app.auth.ldap import authenticate as ldap_authenticate
from app.auth.security import hash_password, needs_rehash, verify_password
from app.core.security import decrypt_secret
from app.db.models.app_settings import AppSettings
from app.db.models.role import Permission, Role
from app.db.models.totp_recovery_code import TotpRecoveryCode
from app.db.models.user import AuthProvider, User

_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_DURATION = timedelta(minutes=15)


async def find_user_for_login(db: AsyncSession, username: str) -> User | None:
    normalized = username.strip().lower()
    if not normalized:
        return None
    result = await db.execute(
        select(User)
        .options(selectinload(User.role).selectinload(Role.permission_grants))
        .where(User.username == normalized)
    )
    return result.scalar_one_or_none()


async def _register_failed_attempt(db: AsyncSession, user: User) -> None:
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= _MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.now(UTC) + _LOCKOUT_DURATION
    await db.commit()


async def _reset_failed_attempts(db: AsyncSession, user: User) -> None:
    if user.failed_login_attempts or user.locked_until is not None:
        user.failed_login_attempts = 0
        user.locked_until = None
        await db.commit()


@dataclass(frozen=True)
class PasswordCheckResult:
    ok: bool
    user: User | None
    # "invalid_credentials" | "locked_out" | "provider_unavailable"
    reason: str
    locked_until: datetime | None = None


async def check_password(
    db: AsyncSession, app_settings: AppSettings, username: str, password: str
) -> PasswordCheckResult:
    user = await find_user_for_login(db, username)
    if user is None or not user.is_active or user.auth_provider == AuthProvider.OIDC:
        return PasswordCheckResult(ok=False, user=None, reason="invalid_credentials")

    if user.is_locked_out:
        return PasswordCheckResult(
            ok=False, user=user, reason="locked_out", locked_until=user.locked_until
        )

    if user.auth_provider == AuthProvider.LOCAL:
        if user.password_hash is None or not verify_password(user.password_hash, password):
            await _register_failed_attempt(db, user)
            return PasswordCheckResult(ok=False, user=user, reason="invalid_credentials")
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
            await db.commit()
    else:  # AuthProvider.LDAP
        try:
            ok = await ldap_authenticate(app_settings, user.username, password)
        except LdapUnavailableError:
            return PasswordCheckResult(ok=False, user=user, reason="provider_unavailable")
        if not ok:
            await _register_failed_attempt(db, user)
            return PasswordCheckResult(ok=False, user=user, reason="invalid_credentials")

    await _reset_failed_attempts(db, user)
    return PasswordCheckResult(ok=True, user=user, reason="")


async def consume_recovery_code(db: AsyncSession, user: User, code: str) -> bool:
    """Checks `code` against `user`'s unused TOTP recovery codes, marking one
    used on a match. Public — also used outside the login flow, by the
    "disable 2FA" / "regenerate recovery codes" confirmations in
    `app/web/routes/auth.py`, which need the same check without the
    lockout side effects `verify_totp_step` applies (those are only
    appropriate mid-login, before the user has proven anything at all)."""
    result = await db.execute(
        select(TotpRecoveryCode).where(
            TotpRecoveryCode.user_id == user.id, TotpRecoveryCode.used_at.is_(None)
        )
    )
    for recovery_code in result.scalars().all():
        if verify_password(recovery_code.code_hash, code):
            recovery_code.used_at = datetime.now(UTC)
            await db.commit()
            return True
    return False


async def verify_totp_step(db: AsyncSession, user: User, code: str) -> bool:
    """Checks a TOTP code or a recovery code against `user`, applying the
    same lockout bookkeeping as the password step."""
    if user.is_locked_out:
        return False

    code = code.strip()
    matched = False
    if code and user.totp_secret_encrypted is not None:
        secret = decrypt_secret(user.totp_secret_encrypted)
        matched = totp_module.verify_code(secret, code)
    if not matched and code:
        matched = await consume_recovery_code(db, user, code)

    if matched:
        await _reset_failed_attempts(db, user)
        return True
    await _register_failed_attempt(db, user)
    return False


async def count_active_users_with_permission(
    db: AsyncSession,
    permission: Permission,
    *,
    excluding_user_id: uuid.UUID | None = None,
    excluding_role_id: uuid.UUID | None = None,
) -> int:
    """Used to block a change that would leave nobody able to manage users
    (see `app/web/routes/users.py` and `app/web/routes/roles.py`) — counts
    active users whose role grants `permission`, directly or via a MANAGE
    permission that implies it.

    `excluding_user_id` simulates deactivating/deleting/demoting one user;
    `excluding_role_id` simulates stripping the permission from one role
    (every active user currently holding that role) — used when *editing a
    role's* permissions rather than one user directly. Since each user has
    exactly one role, both are just "pretend these accounts don't count".

    Done in Python, not SQL, since the implication logic
    (`User.has_permission`) isn't worth reimplementing as a query — this
    table is small (operators, not machines) and this only runs on a rare,
    already-slow-path admin action.
    """
    result = await db.execute(
        select(User)
        .options(selectinload(User.role).selectinload(Role.permission_grants))
        .where(User.is_active.is_(True))
    )
    users = result.scalars().all()
    return sum(
        1
        for u in users
        if u.id != excluding_user_id
        and u.role_id != excluding_role_id
        and u.has_permission(permission)
    )
