"""Model spravovaného Debian stroje."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Enum, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuthMethod(enum.StrEnum):
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"


class Machine(Base):
    """Jeden Debian stroj spravovaný přes SSH.

    Bezpečnostní poznámky:
    - `secret_encrypted` obsahuje heslo nebo privátní klíč zašifrovaný přes
      `app.core.security.encrypt_secret` — v DB nikdy nic v čitelné podobě.
    - `host_key_fingerprint` je otisk SSH host klíče, na který je stroj
      "připnutý" (pinning). Dokud není nastaven, spojení se strojem se
      NEnaváže automaticky (žádné tiché "trust on first use") — otisk musí
      být explicitně potvrzen obsluhou mimo tuto aplikaci (např. konzolí
      poskytovatele) a teprve pak uložen.
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

    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - jen pro ladění
        return f"Machine(id={self.id!r}, hostname={self.hostname!r})"
