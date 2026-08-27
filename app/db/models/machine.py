"""Model for a managed Debian machine."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.machine_group import MachineGroup


class AuthMethod(enum.StrEnum):
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"


class Machine(Base):
    """A single Debian machine managed over SSH.

    Security notes:
    - `secret_encrypted` holds a password or private key, encrypted via
      `app.core.security.encrypt_secret` — nothing sensitive is ever stored
      in the DB in plaintext.
    - `host_key_fingerprint` is the SSH host key fingerprint this machine is
      "pinned" to. Until it's set, no connection to the machine will be
      established automatically (no silent "trust on first use") — the
      fingerprint must be explicitly confirmed by an operator outside this
      application (e.g. via the hosting provider's console) and only then
      stored here.
    """

    __tablename__ = "machines"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(default=22, nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)

    auth_method: Mapped[AuthMethod] = mapped_column(
        Enum(AuthMethod, name="auth_method", native_enum=True),
        nullable=False,
    )
    secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    host_key_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)

    group_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("machine_groups.id", ondelete="SET NULL"), nullable=True
    )
    group: Mapped[MachineGroup | None] = relationship(back_populates="machines")

    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"Machine(id={self.id!r}, hostname={self.hostname!r})"
