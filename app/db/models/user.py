"""debcontrol user accounts.

Every account is created inside debcontrol first — there's no auto-provisioning
from LDAP or OIDC (see `app.auth.login`, `app.auth.oidc`). `auth_provider`
just decides *how* that account proves who it is:

- `LOCAL`: a password stored here (`password_hash`, argon2id — see
  `app.auth.security`).
- `LDAP`: binds against the directory configured in Settings, using this
  account's `username` as the LDAP username — no separate field for that
  (see `app.auth.ldap`).
- `OIDC`: redirected to the configured provider; the account is matched by
  comparing `username` against a claim from the ID token (which claim is
  configurable in Settings — `app.db.models.app_settings.AppSettings.oidc_username_claim`).

`LOCAL` and `LDAP` accounts can additionally enroll TOTP (`app.auth.totp`);
`OIDC` accounts can't — the provider's own MFA (if any) is what backs that
login instead.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Integer, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.role import Permission, Role
from app.db.pg_enum import pg_enum

if TYPE_CHECKING:
    from app.db.models.api_token import ApiToken
    from app.db.models.totp_recovery_code import TotpRecoveryCode
    from app.db.models.user_session import UserSession


class AuthProvider(enum.StrEnum):
    LOCAL = "local"
    LDAP = "ldap"
    OIDC = "oidc"


# A MANAGE permission always also grants the matching VIEW permission — see
# app/db/models/role.py's module docstring for why.
_MANAGE_IMPLIES_VIEW: dict[Permission, Permission] = {
    Permission.MACHINE_MANAGE: Permission.MACHINE_VIEW,
    Permission.GROUP_MANAGE: Permission.GROUP_VIEW,
    Permission.SCHEDULING_MANAGE: Permission.SCHEDULING_VIEW,
    Permission.SETTINGS_MANAGE: Permission.SETTINGS_VIEW,
}


def role_has_permission(role: Role, permission: Permission) -> bool:
    """The check behind `User.has_permission`, taking a `Role` directly —
    used where there's a role to check against but no (or not yet a saved)
    `User` row, e.g. `app/web/routes/users.py` simulating "if this user's
    role were changed to X, would they still have `user.manage`?" before
    committing a change that might remove the last account able to grant it
    back."""
    granted = role.permissions
    if permission in granted:
        return True
    implying_manage = next(
        (manage for manage, view in _MANAGE_IMPLIES_VIEW.items() if view == permission), None
    )
    return implying_manage is not None and implying_manage in granted


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    # Always stored lowercased (app.schemas.user normalizes it) — the login
    # identifier, the LDAP bind username, and (compared against a claim) the
    # OIDC identity, all at once. See the module docstring.
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    auth_provider: Mapped[AuthProvider] = mapped_column(
        pg_enum(AuthProvider, name="auth_provider"), nullable=False
    )
    # Only ever set for AuthProvider.LOCAL.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Set when an admin assigns a new password (creation, or a reset) — the
    # user is forced to pick their own before doing anything else. Never set
    # for LDAP/OIDC accounts (there's no debcontrol-side password to change).
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # A disabled account can't log in and gets no new sessions, but is kept
    # (not deleted) so its username stays out of the audit trail's history
    # without orphaning past entries. Deleting a user is still possible
    # separately (see app/web/routes/users.py) — this is for "revoke access
    # without losing the record of who did what."
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Whether this user is allowed to create/use API tokens at all — a
    # separate, admin-set flag on the account itself, distinct from the
    # role-based Permission matrix (a role's permissions decide *what* a
    # token can do; this decides *whether the account may have one in the
    # first place*). Checked both at token-creation time
    # (`app/web/routes/auth.py`'s `create_own_api_token`) and live on every
    # API request (`app.auth.api_tokens.get_user_for_api_token`, right next
    # to the `is_active` check) — so unchecking it cuts off that user's
    # existing tokens immediately, the same way deactivating the account
    # already does, with no separate revocation step needed.
    api_access_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # --- TOTP (see app.auth.totp) — available for LOCAL and LDAP, not OIDC ---
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_confirmed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Brute-force lockout — shared by password checks and TOTP checks,
    # see app.auth.login. Reset to 0/None on any successful login step. ---
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(nullable=True)

    last_login_at: Mapped[datetime | None] = mapped_column(nullable=True)

    role_id: Mapped[uuid.UUID] = mapped_column(
        # No ondelete= — defaults to RESTRICT, so the DB itself refuses to
        # delete a role that's still assigned to a user. See
        # app/db/models/role.py.
        ForeignKey("roles.id"),
        nullable=False,
    )
    role: Mapped[Role] = relationship(back_populates="users", lazy="joined")

    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    totp_recovery_codes: Mapped[list[TotpRecoveryCode]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    api_tokens: Mapped[list[ApiToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def has_permission(self, permission: Permission) -> bool:
        """Does this user's role grant `permission` — directly, or via a
        MANAGE permission that implies it?"""
        return role_has_permission(self.role, permission)

    @property
    def is_locked_out(self) -> bool:
        if self.locked_until is None:
            return False
        now = datetime.now(UTC)
        if self.locked_until.tzinfo is not None:
            return self.locked_until > now
        # Naive value (e.g. read back from SQLite in tests, which drops
        # tzinfo on round-trip) — this app always writes `locked_until` as
        # UTC, so a naive value here is treated as already being UTC rather
        # than local time. Same reasoning as app.audit._normalized_timestamp.
        return self.locked_until > now.replace(tzinfo=None)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"User(id={self.id!r}, username={self.username!r})"
