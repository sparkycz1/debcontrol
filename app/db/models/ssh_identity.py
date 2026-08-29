"""The application's own shared SSH identity.

debcontrol connects to managed machines using one SSH keypair that belongs
to the application itself, rather than a separate key per machine.
Distributing the *public* half to machines (appending it to
`~/.ssh/authorized_keys`) is a manual step for an operator today — see the
wiki page "Managed Machine Requirements".

The private key is generated once, on first use, and stored encrypted
(`app.core.security.encrypt_secret`) — never in plaintext, never on disk.
This is a singleton table: exactly one row, with a fixed id.

Rotation (see `app.ssh.identity.generate_pending_identity`/
`activate_pending_identity`) works by generating a *second* keypair into the
`pending_*` columns alongside the active one, rather than replacing the
active key immediately — every already-configured machine's
`authorized_keys` still only has the old public key until an operator adds
the new one, so switching the active key before that would lock the app out
of every machine at once. The pending key sits there (visible on the
Settings page for the operator to copy into `authorized_keys`) until they
confirm it's rolled out and activate it, which moves it into the `public_key`/
`private_key_encrypted`/`fingerprint` columns and clears `pending_*`.
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

    # --- A generated-but-not-yet-active replacement key (rotation) ---
    pending_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    pending_private_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    pending_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pending_generated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"SSHIdentity(fingerprint={self.fingerprint!r})"
