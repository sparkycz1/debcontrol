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
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.pg_enum import pg_enum

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
    `security_upgradable_count` (apt) and `flatpak_upgradable_count` /
    `snap_upgradable_count` come from a separate, root-requiring check (see
    `app.ssh.updates.check_updates`) on the same refresh schedule, also
    stamped in `updates_checked_at`. The actual installed-package list
    (apt/flatpak/snap, with versions) doesn't live on this model — it's a
    separate `MachinePackage` row per package, refreshed on the same
    schedule (`packages_updated_at`) and additionally right after a
    machine's own update run finishes — see `app.tasks.jobs`.
    """

    __tablename__ = "machines"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    # Indexed: the machines list orders/searches by this, and every fleet-
    # wide sweep filters on `is_active` (below) — both scans get expensive
    # doing a full table scan once the fleet is in the hundreds/thousands.
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(default=22, nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)

    auth_method: Mapped[AuthMethod] = mapped_column(
        pg_enum(AuthMethod, name="auth_method"),
        nullable=False,
    )
    secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    host_key_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)

    group_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("machine_groups.id", ondelete="SET NULL"), nullable=True, index=True
    )
    group: Mapped[MachineGroup | None] = relationship(back_populates="machines")

    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False, index=True)

    # --- Facts, discovered over SSH (see app.ssh.facts) ---
    discovered_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kernel_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpu_architecture: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cpu_cores: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cpu_model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ram_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # None = couldn't tell (no dmidecode access) — see app.ssh.facts.FACTS_COMMAND.
    ram_speed_mhz: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # `/etc/os-release`'s `ID=` field (e.g. "debian", "ubuntu", "linuxmint",
    # "proxmox", "fedora") — deliberately separate from `os_version` (that
    # one's `PRETTY_NAME=`, meant to be read by a human, not matched against
    # a logo lookup table). Used only to pick which OS logo to show next to
    # the machine's name — see app.web.os_logos.
    os_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    disks: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # None = never determined either way (e.g. no dpkg/linux-image-* found).
    reboot_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Seconds since boot (`/proc/uptime`) and a snapshot process count
    # (`ls /proc/[0-9]*`) — both refreshed alongside the rest of the facts.
    uptime_seconds: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    process_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Each a list of dicts (see app.ssh.facts.parse_facts_output) — mounted
    # filesystems' used/free/percent (via `df`, pseudo-filesystems excluded),
    # and IPv4 addresses per network interface (via `ip addr`).
    filesystems: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    network_interfaces: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    facts_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Cheap per-minute reachability check (TCP connect to the SSH port) ---
    is_reachable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_ping_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Per-machine overrides of the global `.env` sweep cadences
    # (`REACHABILITY_CHECK_INTERVAL_SECONDS`/`FACTS_REFRESH_INTERVAL_SECONDS`)
    # — NULL means "use the global default". Both sweeps still tick at the
    # global interval (Celery Beat's schedule is one fixed cadence, not
    # per-machine); a machine with a *larger* effective interval than the
    # global one is simply skipped on ticks that come too soon after its
    # last check — see app.tasks.jobs._due_machines. A machine can't be
    # checked *more* often than the global tick rate this way, only less.
    reachability_check_interval_seconds: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    facts_refresh_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Same idea, for `MONITORING_INTERVAL_SECONDS` (see app.ssh.monitoring).
    monitoring_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Overrides `AppSettings.monitoring_history_retention_days` (the
    # *global* default, editable in Settings — NOT a `.env` value, unlike
    # the interval above; see that column's own docstring) for just this
    # machine. NULL means "use the global setting".
    monitoring_history_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # --- Monitoring tab: CPU/RAM/disk-usage samples (app.db.models.
    # machine_monitoring_sample.MachineMonitoringSample) and the systemd
    # service snapshot (app.db.models.machine_service.MachineService) ---
    monitoring_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)
    services_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Update availability: apt, flatpak, snap (requires root/sudo for
    # apt-get update; flatpak/snap listing is read-only — see app.ssh.updates) ---
    upgradable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    security_upgradable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    flatpak_upgradable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snap_upgradable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updates_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # Which packages, not just how many — each a {name, current_version,
    # new_version} dict (see app.ssh.updates.PendingPackage). Populated by
    # the same check_machine_updates job as the counts above, whether it
    # ran from the periodic sweep, the "Check for updates now" button, or a
    # scheduled task the user set up — there's no separate code path for
    # "scheduled" checks, so this is only ever as fresh as the last check.
    apt_upgradable_packages: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON, nullable=True
    )
    flatpak_upgradable_packages: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON, nullable=True
    )
    snap_upgradable_packages: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON, nullable=True
    )

    # --- Installed-package snapshot (see MachinePackage / app.ssh.packages) ---
    packages_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"Machine(id={self.id!r}, name={self.name!r})"
