"""One-time TOTP recovery codes — generated once at enrollment (see
`app.auth.totp`) so a user who loses their authenticator device can still get
in. Each code is single-use: `used_at` is set the moment one is consumed, and
a used or never-issued code is never accepted again.

Stored hashed with the same hasher as passwords (`app.auth.security`) — a
recovery code is functionally a backup password.
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


class TotpRecoveryCode(Base):
    __tablename__ = "totp_recovery_codes"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user: Mapped[User] = relationship(back_populates="totp_recovery_codes")

    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        used = self.used_at is not None
        return f"TotpRecoveryCode(id={self.id!r}, user_id={self.user_id!r}, used={used!r})"
