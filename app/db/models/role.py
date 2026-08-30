"""Roles and permissions — the "complete RBAC" layer: an admin defines named
roles (e.g. "Operator", "Auditor") and picks exactly which permissions each
one grants, then assigns one role to each user (see `app.db.models.user`).

Permissions are deliberately resource-grained, not per-object — there's no
"can manage machine X but not machine Y" here, only "can manage machines at
all". `MANAGE` implies `VIEW` for the same resource (see `_MANAGE_IMPLIES_VIEW`
and `User.has_permission` in `app.db.models.user`) so a role granted e.g.
`MACHINE_MANAGE` doesn't also need `MACHINE_VIEW` ticked separately — that
would be a footgun (a role that can edit machines but, by omission, can't
even load the page listing them).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.pg_enum import pg_enum

if TYPE_CHECKING:
    from app.db.models.user import User


class Permission(enum.StrEnum):
    MACHINE_VIEW = "machine.view"
    MACHINE_MANAGE = "machine.manage"
    GROUP_VIEW = "group.view"
    GROUP_MANAGE = "group.manage"
    # Triggering "check for updates" / "run updates", per-machine, per-group,
    # or against all machines — separate from MACHINE_MANAGE since running
    # updates isn't the same trust level as editing a machine's connection
    # details, and separate from ACTION_POWER since it isn't destructive.
    ACTION_UPDATES = "action.updates"
    # Reboot/shutdown/power-off — kept apart from ACTION_UPDATES since it's
    # destructive (see `destructive=True` on scheduled actions) and often
    # warrants a smaller set of trusted people than "can run apt upgrade".
    ACTION_POWER = "action.power"
    SCHEDULING_VIEW = "scheduling.view"
    SCHEDULING_MANAGE = "scheduling.manage"
    AUDIT_VIEW = "audit.view"
    SETTINGS_VIEW = "settings.view"
    SETTINGS_MANAGE = "settings.manage"
    # Users, roles, and sessions ("log out everywhere") are bundled under one
    # permission rather than split further — none of it is meaningful
    # without the others (a role editor who can't also assign roles to users
    # isn't useful on its own).
    USER_MANAGE = "user.manage"


class Role(Base):
    """A named, reusable set of permissions."""

    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # When true, every user holding this role must have `User.totp_enabled`
    # to do anything except enroll TOTP or log out — enforced live, on every
    # request, in `app.auth.middleware` (session requests) and
    # `app.auth.dependencies.get_api_token_user` (API-token requests), not
    # just steered at login time like `User.must_change_password` is. See
    # those modules for the enforcement and wiki/Architecture.md for the
    # OIDC-exemption reasoning (OIDC accounts can't enroll TOTP here at all —
    # a role with this set would otherwise lock them out unconditionally).
    require_totp: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # lazy="selectin": always loaded (one small extra batched query) whenever
    # a Role is, rather than lazy — with the async ORM, a genuinely lazy
    # load here would raise MissingGreenlet the moment anything (like
    # `permissions`/`User.has_permission`) reads it outside of an explicit
    # `selectinload(...)` the caller remembered to add. Roles are few and
    # rarely reloaded, so paying for this eagerly, always, is cheap
    # insurance against that whole class of bug.
    permission_grants: Mapped[list[RolePermission]] = relationship(
        back_populates="role", cascade="all, delete-orphan", lazy="selectin"
    )
    # ON DELETE RESTRICT (the default for a FK without ondelete=) on
    # User.role_id means the DB itself refuses to delete a role that's still
    # assigned to anyone — belt-and-braces alongside the application-level
    # check in app/web/routes/roles.py.
    users: Mapped[list[User]] = relationship(back_populates="role")

    @property
    def permissions(self) -> frozenset[Permission]:
        return frozenset(grant.permission for grant in self.permission_grants)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"Role(id={self.id!r}, name={self.name!r})"


class RolePermission(Base):
    """One granted permission for one role — a plain association row, not a
    catalog table, since `Permission` is a fixed, code-defined set rather
    than data an admin creates."""

    __tablename__ = "role_permissions"

    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission: Mapped[Permission] = mapped_column(
        pg_enum(Permission, name="permission"), primary_key=True
    )

    role: Mapped[Role] = relationship(back_populates="permission_grants")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"RolePermission(role_id={self.role_id!r}, permission={self.permission!r})"
