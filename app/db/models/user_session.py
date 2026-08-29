"""Server-side login sessions — deliberately not a stateless signed cookie
(a JWT-in-a-cookie, say), even though `SECRET_KEY` is available for that.
A row per session here is what makes a session immediately revocable: an
admin disabling a user, a user changing their password, or "log out
everywhere" all just need to delete/expire rows — nothing to do with
waiting out a token's own expiry. See `app.auth.sessions`.

Named `UserSession`, not `Session`, to avoid any confusion with SQLAlchemy's
own `Session`/`AsyncSession`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.user import User


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user: Mapped[User] = relationship(back_populates="sessions")

    # SHA-256 hex digest of the raw token that actually sits in the client's
    # cookie — the raw value is never stored, so a DB leak alone doesn't hand
    # over any live session (same reasoning as password hashing, just a
    # plain fast hash here since the input already has 256 bits of entropy,
    # not a low-entropy secret an attacker could feasibly guess/brute force).
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)

    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"UserSession(id={self.id!r}, user_id={self.user_id!r})"
