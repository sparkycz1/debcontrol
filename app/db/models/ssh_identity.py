"""The application's own shared SSH identity.

debcontrol connects to managed machines using one SSH keypair that belongs
to the application itself, rather than a separate key per machine.
Distributing the *public* half to machines (appending it to
`~/.ssh/authorized_keys`) is a manual step for an operator today — see the
wiki page "Managed Machine Requirements".

The private key is generated once, on first use, and stored encrypted
(`app.core.security.encrypt_secret`) — never in plaintext, never on disk.
This is a singleton table: exactly one row, with a fixed id.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import LargeBinary, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

SINGLETON_ID = 1


class SSHIdentity(Base):
    __tablename__ = "ssh_identity"

    id: Mapped[int] = mapped_column(primary_key=True)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    private_key_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"SSHIdentity(fingerprint={self.fingerprint!r})"
