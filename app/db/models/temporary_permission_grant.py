"""A time-limited, per-*user* permission grant — "this account gets
`action.terminal` for the next 2 hours" — on top of (never replacing)
whatever its `Role` already grants. Expiry is checked live, the same way
a session's own expiry is: there is no background job that "turns off"
an expired grant, `User.has_permission` (see that module) simply stops
counting it once `expires_at` has passed. An admin can also revoke one
early (`revoked_at`), for the same reasons a session can be force-ended.

Deliberately per-user rather than a time-limited *role* — a role is
shared fleet-wide configuration; a temporary grant is "just this one
person, just for now," which a role was never meant to model and would
otherwise need a disposable one-off role per grant.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.permission import Permission
from app.db.pg_enum import pg_enum


class TemporaryPermissionGrant(Base):
    __tablename__ = "temporary_permission_grants"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user: Mapped[User] = relationship(
        back_populates="temporary_permission_grants", foreign_keys=[user_id]
    )

    permission: Mapped[Permission] = mapped_column(
        pg_enum(Permission, name="permission"), nullable=False
    )

    # Who granted it — kept for the audit trail even if that admin's own
    # account is later deleted (SET NULL, not a FK the grant itself
    # depends on staying valid).
    granted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    granted_by: Mapped[User | None] = relationship(foreign_keys=[granted_by_id])

    granted_at: Mapped[datetime] = mapped_column(nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    # Set if an admin ended it early — an expired-but-not-yet-passed grant
    # (expires_at in the future) stops counting immediately either way;
    # this is just how "revoked early" is distinguished from "ran its
    # course" when looking at the list later.
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return expires_at > datetime.now(UTC)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"TemporaryPermissionGrant(user_id={self.user_id!r}, permission={self.permission!r})"


# Imported last, and only for type checking: every class above is already
# defined by the time this module points back at the models it relates
# to, so no import cycle can leave a class half-defined (CodeQL's
# "Module-level cyclic import"). SQLAlchemy resolves the relationship
# targets by name through its registry, never through these imports.
if TYPE_CHECKING:
    from app.db.models.user import User
