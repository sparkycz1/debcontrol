"""Model for a managed Debian machine."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.machine_group import MachineGroup


class AuthMethod(enum.StrEnum):
    SSH_KEY = "ssh_key"
    PASSWORD = "password"


class Machine(Base):
    """A single Debian machine managed over SSH.

    Security notes:
    - `secret_encrypted` only holds a value for `AuthMethod.PASSWORD` (the
      discouraged fallback) — encrypted via `app.core.security.encrypt_secret`.
      For `AuthMethod.SSH_KEY` (the default/recommended method), the app
      connects using its own shared identity key (see
      `app.db.models.ssh_identity.SSHIdentity`), so there's nothing
      machine-specific to store.
    - `host_key_fingerprint` is the SSH host key fingerprint this machine is
      "pinned" to. Until it's set, no connection to the machine will be
      established automatically (no silent "trust on first use") — the
      fingerprint must be explicitly confirmed by an operator outside this
      application (e.g. via the hosting provider's console) and only then
      stored here.

    Facts (`os_version`, `kernel_version`, `cpu_cores`, `ram_bytes`, `disks`,
    `discovered_hostname`, `reboot_required`) are read from the machine
    itself over SSH — see `app.ssh.facts` — once a host key fingerprint is
    pinned, and refreshed periodically by the background worker
    (`FACTS_REFRESH_INTERVAL_SECONDS`). None of that needs root.
    `is_reachable`/`last_ping_at` come from a much cheaper, unauthenticated
    TCP-reachability check run every minute. `upgradable_count` /
    `security_upgradable_count` / `updates_checked_at` come from a
    separate, root-requiring check (see `app.ssh.updates.check_updates`) on
    the same refresh schedule.
    """

    __tablename__ = "machines"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(255), nullable=False)
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

    # --- Facts, discovered over SSH (see app.ssh.facts) ---
    discovered_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kernel_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpu_cores: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ram_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    disks: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # None = never determined either way (e.g. no dpkg/linux-image-* found).
    reboot_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    facts_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Cheap per-minute reachability check (TCP connect to the SSH port) ---
    is_reachable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_ping_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- apt update availability (requires root/sudo — see app.ssh.updates) ---
    upgradable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    security_upgradable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updates_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"Machine(id={self.id!r}, name={self.name!r})"
