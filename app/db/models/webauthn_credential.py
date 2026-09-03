"""A registered WebAuthn credential (a passkey — a platform authenticator
like Touch ID/Windows Hello, or a hardware security key) — a second login
factor alongside TOTP, or in its place. See `app.auth.webauthn` for the
registration/authentication ceremony logic that creates and verifies
these, and `wiki/Architecture.md`'s "WebAuthn/passkeys" section for the
full design.

Available to `local` and `ldap` accounts, same restriction (and reasoning)
as `app.auth.totp` — an `oidc` account's provider owns its own MFA.

Nothing here is a secret: `public_key` is exactly what its name says, a
public key — the private key never leaves the authenticator (that's the
entire point of WebAuthn). Stored to *verify* a signature, never to
produce one.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Integer, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.user import User


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user: Mapped[User] = relationship(back_populates="webauthn_credentials")

    # A label the account owner picks at registration time ("YubiKey",
    # "MacBook Touch ID") — purely for their own benefit telling entries
    # apart on the Account page; never used to identify the credential to
    # the authenticator or the relying-party protocol itself.
    name: Mapped[str] = mapped_column(String(100), nullable=False)

    # The authenticator's own opaque credential id — what the browser sends
    # back on every subsequent authentication so the server knows which
    # public key to verify the signature against. Unique per credential
    # (never reused across authenticators or accounts).
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # The authenticator's own signature counter, as of the last successful
    # use — required by the WebAuthn spec to detect a cloned authenticator
    # (a counter that goes backwards, or repeats, on a later use means two
    # devices are presenting the same credential). See
    # `app.auth.webauthn.verify_authentication`.
    sign_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # "single_device" (a hardware key, not synced) vs "multi_device" (a
    # passkey synced via iCloud Keychain/Google Password Manager/etc.) —
    # display-only context on the Account page, not used to gate anything.
    device_type: Mapped[str] = mapped_column(String(32), nullable=False)
    backed_up: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"WebAuthnCredential(id={self.id!r}, user_id={self.user_id!r}, name={self.name!r})"
