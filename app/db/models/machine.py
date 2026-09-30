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
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.machine_tag import Tag, machine_tags
from app.db.pg_enum import pg_enum


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

    @property
    def os_display(self) -> str | None:
        """The OS as shown to people: "Proxmox VE 8.2.4 (Debian GNU/Linux
        12 (bookworm))" on a Proxmox VE / Backup Server / Mail Gateway host —
        whose /etc/os-release only says Debian — else the plain
        `os_version`."""
        product = self.proxmox_product
        if product:
            return f"{product} ({self.os_version})" if self.os_version else product
        return self.os_version

    @property
    def proxmox_product(self) -> str | None:
        """"Proxmox VE 8.2.4" / "Proxmox Backup Server 3.2.7" / "Proxmox
        Mail Gateway 8.1.4" — whichever this machine runs, else None."""
        if self.pve_version:
            return f"Proxmox VE {self.pve_version}"
        if self.pbs_version:
            return f"Proxmox Backup Server {self.pbs_version}"
        if self.pmg_version:
            return f"Proxmox Mail Gateway {self.pmg_version}"
        return None

    @property
    def has_proxmox_tab(self) -> bool:
        """Proxmox VE / Backup Server / Mail Gateway data, or ZFS pools."""
        return bool(
            self.pve_version
            or self.pve_guests is not None
            or self.pbs_version
            or self.pmg_version
            or self.zfs_pools
        )

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

    # Free-form, cross-cutting labels independent of `group` above — see
    # app.db.models.machine_tag's own docstring. `order_by` keeps the list
    # alphabetical everywhere it's rendered/serialized without every caller
    # needing to sort it itself.
    tags: Mapped[list[Tag]] = relationship(
        secondary=machine_tags, order_by="Tag.name", lazy="selectin"
    )

    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # A longer, Markdown-formatted runbook — "how to deal with this
    # server, who owns it" — separate from `description` above (a short,
    # searchable one-liner used in the machine list) since the two serve
    # different purposes and a runbook can reasonably run to several
    # paragraphs. Rendered via app.web.templating's `markdown` filter
    # (mistune, HTML-escaped by default — see that filter's docstring).
    runbook: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    # Listening TCP `address:port`s, local admin accounts and local login
    # accounts (see app.ssh.facts) — refreshed with the facts and compared
    # against the previous refresh by app.services.config_drift.
    listening_ports: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    admin_users: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    login_users: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    # Detected via `systemd-detect-virt` (see app.ssh.facts) — True on bare
    # metal, False inside a VM/container, None if it couldn't be
    # determined (no systemd-detect-virt binary). Gates whether the
    # Monitoring sample round trip also probes hardware sensors/fans/
    # S.M.A.R.T./power draw (app.ssh.monitoring) — none of that is
    # meaningful, and S.M.A.R.T. in particular is actively misleading,
    # against a virtual disk.
    is_physical: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # Full per-disk S.M.A.R.T. detail (app.ssh.smart), refreshed with facts
    # — a snapshot, not a history. None = not applicable (VM / no smartctl).
    smart_devices: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    facts_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Proxmox VE / ZFS (app.ssh.proxmox). Version, storages and backups
    # come with the facts refresh; guests and pools with every monitoring
    # sample. All None on a machine without Proxmox VE / ZFS. ---
    pve_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    pve_storage: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # {"tasks": [...], "jobs": [...], "not_backed_up": [...]}
    pve_backups: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    pve_guests: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # {"name", "quorate", "nodes": [...]} (monitoring sample) and the last
    # failed tasks of any kind (facts refresh) — Proxmox VE.
    pve_cluster: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    pve_failed_tasks: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # Proxmox Backup Server / Mail Gateway (facts refresh; app.ssh.proxmox
    # parse_pbs / parse_pmg for the shape). None on anything else.
    pbs_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    pbs_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    pmg_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    pmg_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # systemd units in the failed state as of the latest monitoring sample
    # (None = unknown / no systemd) — the "service failed" notification
    # compares against it (app.services.health_events).
    failed_units: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    zfs_pools: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # {mount: {"bytes_per_day", "days_until_full", "used_bytes", "size_bytes"}}
    # — see app.services.disk_forecast; recomputed hourly.
    disk_forecast: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # --- Docker, refreshed with every monitoring sample (app.ssh.monitoring).
    # `docker_status`: None = no docker CLI, "no_access" = present but this
    # account can't reach the daemon, "ok". `docker_containers` is the
    # latest full container list (image/state/ports/stats) for the
    # Monitoring tab's table; the per-sample history keeps only the numbers
    # (MachineMonitoringSample.docker_stats).
    docker_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    docker_containers: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # {image: "update" | "current" | "unknown"} for every running image, from
    # the daily registry-digest comparison (app.ssh.image_updates).
    docker_image_updates: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    docker_images_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)

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

    # --- Post-onboarding readiness check (see app.ssh.readiness) ---
    # `readiness_missing`: human-readable descriptions of whatever the last
    # check found not set up (ncurses-term, scoped sudo for apt/shutdown/
    # dmidecode/flatpak+snap) — an empty list means everything checked was
    # fine, `None` means never checked. Re-run automatically right after
    # the host key is confirmed and right after "Run initial setup"
    # completes; otherwise on demand ("Re-check" button) — not on any
    # periodic sweep, this is an onboarding-time nudge, not a monitor.
    readiness_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    readiness_missing: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

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
    # Packages pinned with `apt-mark hold` (never upgraded until released),
    # refreshed with every update check. None = not checked yet.
    apt_held_packages: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # --- Installed-package snapshot (see MachinePackage / app.ssh.packages) ---
    packages_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"Machine(id={self.id!r}, name={self.name!r})"


# Imported last, and only for type checking: every class above is already
# defined by the time this module points back at the models it relates
# to, so no import cycle can leave a class half-defined (CodeQL's
# "Module-level cyclic import"). SQLAlchemy resolves the relationship
# targets by name through its registry, never through these imports.
if TYPE_CHECKING:
    from app.db.models.machine_group import MachineGroup
