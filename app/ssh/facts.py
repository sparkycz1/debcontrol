"""Gather basic facts about a managed machine over SSH.

Deliberately uses only tools present on a stock Debian install (coreutils,
util-linux, dpkg, base-files, iproute2) — no agent, no extra packages
required on the target, and nothing here needs root. See the wiki page
"Machine Requirements".
"""

from __future__ import annotations

import re
from typing import Any, TypedDict

from app.db.models.machine import Machine
from app.ssh import proxmox
from app.ssh.client import open_connection
from app.ssh.pool import machine_connection
from app.ssh.shell import with_root_shim
from app.ssh.smart import SMART_FACTS_SECTION, parse_smart_section

_SECTION_MARKERS = (
    "HOSTNAME",
    "OS",
    "OS_ID",
    "KERNEL",
    "KERNEL_LATEST",
    "ARCH",
    "CPU",
    "CPU_MODEL",
    "RAM_KB",
    "RAM_SPEED",
    "DISKS",
    "UPTIME",
    "PROCESSES",
    "FILESYSTEMS",
    "NETWORK",
    "LISTEN",
    "ADMINS",
    "LOGINS",
    "VIRT",
    "SMART",
    "REBOOT_FLAG",
    *proxmox.INVENTORY_MARKERS,
)

# One round trip: each section is delimited by a "===NAME===" marker so the
# output can be split reliably even if a command prints nothing or errors.
FACTS_COMMAND = (
    "echo ===HOSTNAME===; hostname 2>/dev/null; "
    "echo ===OS===; "
    "(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"'); "
    # `ID=` (e.g. "debian", "ubuntu", "linuxmint") rather than PRETTY_NAME
    # above — machine-readable, meant to be matched against a logo lookup
    # table (app.web.os_logos), not read by a human. Proxmox VE is Debian
    # underneath and doesn't override /etc/os-release at all (`ID=debian`
    # there too) — its own marker is `/etc/pve` (the cluster filesystem
    # mount) or the `pveversion` command, checked first and given priority.
    "echo ===OS_ID===; "
    "if [ -d /etc/pve ] || command -v pveversion >/dev/null 2>&1; then echo proxmox; "
    "else (grep -m1 '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"'); fi; "
    "echo ===KERNEL===; uname -r 2>/dev/null; "
    # Proxmox VE ships its kernels as `proxmox-kernel-<ver>-pve-signed`
    # (older: `pve-kernel-<ver>-pve`), not `linux-image-*` — without them a
    # pending PVE kernel never counted as "reboot required".
    "echo ===KERNEL_LATEST===; "
    "dpkg --list 'linux-image-*' 'proxmox-kernel-*' 'pve-kernel-*' 2>/dev/null "
    "| awk '/^ii/{print $2}' "
    "| sed -E 's/^(linux-image|proxmox-kernel|pve-kernel)-//; s/-signed$//' "
    "| grep -E '^[0-9]' | sort -V | tail -1; "
    "echo ===ARCH===; uname -m 2>/dev/null; "
    "echo ===CPU===; nproc 2>/dev/null; "
    "echo ===CPU_MODEL===; "
    # `lscpu` (util-linux, already assumed present — see module docstring)
    # normalizes this across architectures: `/proc/cpuinfo`'s `model name`
    # field is x86-only — an ARM kernel's `/proc/cpuinfo` (Raspberry Pi,
    # an ARM cloud instance) has no such line at all, silently leaving
    # cpu_model empty. `lscpu`'s own `Model name:` line exists on both —
    # but modern util-linux nests it under `Vendor ID:` in its tree-style
    # output (`  Model name:`, two leading spaces), so the grep here
    # explicitly allows (does not require) leading whitespace rather than
    # anchoring straight to column 1. Falls back to the old /proc/cpuinfo
    # probe only if lscpu itself is somehow missing (a genuinely minimal
    # image without util-linux).
    "(lscpu 2>/dev/null | grep -m1 -E '^[[:space:]]*Model name:' | cut -d: -f2- "
    "| sed -e 's/^ *//' -e 's/ \\+/ /g') || "
    "(grep -m1 '^model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed -e 's/^ *//' "
    "-e 's/ \\+/ /g'); "
    "echo ===RAM_KB===; awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null; "
    # Memory clock speed isn't exposed anywhere a non-root user can read (no
    # /proc//sys entry for it) — only `dmidecode` (SMBIOS type 17) has it,
    # and that needs root. This only produces output when the machine's
    # sudoers rule (see app.ssh.onboarding) actually grants passwordless
    # dmidecode, or the account itself is root; otherwise RAM_SPEED stays
    # empty and `ram_speed_mhz` is None, same "couldn't tell" convention as
    # `reboot_required`.
    "echo ===RAM_SPEED===; "
    "(sudo -n dmidecode -t 17 2>/dev/null || dmidecode -t 17 2>/dev/null) "
    "| awk '/^[[:space:]]*Speed:/ && $2 ~ /^[0-9]+$/ {print $2; exit}'; "
    "echo ===DISKS===; "
    "lsblk -b -d -n -o NAME,SIZE,TYPE 2>/dev/null | awk '$3==\"disk\"{print $1, $2}'; "
    "echo ===UPTIME===; awk '{print int($1)}' /proc/uptime 2>/dev/null; "
    "echo ===PROCESSES===; ls -d /proc/[0-9]* 2>/dev/null | wc -l; "
    "echo ===FILESYSTEMS===; "
    "df -B1 --output=target,size,used,avail,pcent "
    "-x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2; "
    "echo ===NETWORK===; "
    "ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}'; "
    # Listening TCP sockets, local address:port only (`ss` is iproute2,
    # like `ip` above; no root needed for the addresses, only for the
    # owning process, which isn't asked for). Config-drift input — see
    # app.services.config_drift.
    "echo ===LISTEN===; ss -Htln 2>/dev/null | awk '{print $4}'; "
    # Local accounts with admin rights (members of sudo/wheel/admin, plus
    # every uid 0 account) and local login accounts (uid 1000-65533) —
    # read from the local /etc files, never `getent`, so a machine joined
    # to LDAP/AD doesn't enumerate its whole directory on every refresh.
    "echo ===ADMINS===; "
    "awk -F: '$1==\"sudo\"||$1==\"wheel\"||$1==\"admin\"{print $4}' /etc/group 2>/dev/null "
    "| tr ',' '\\n'; awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null; "
    "echo ===LOGINS===; awk -F: '$3>=1000&&$3<65534{print $1}' /etc/passwd 2>/dev/null; "
    # `systemd-detect-virt` prints "none" and exits 1 on bare metal, or the
    # hypervisor/container technology name (and exits 0) inside one — the
    # standard, widely-available way to tell (ships with systemd itself,
    # already assumed present per this module's own conventions elsewhere).
    # Gates whether app.ssh.monitoring also probes hardware sensors/fans/
    # S.M.A.R.T./power draw, none of which is meaningful (S.M.A.R.T.
    # actively misleading) against a virtual disk. Missing binary or any
    # other failure leaves this empty — "couldn't tell", same convention
    # as reboot_required/ram_speed_mhz above, never assumed either way.
    "echo ===VIRT===; "
    "if command -v systemd-detect-virt >/dev/null 2>&1; then "
    "systemd-detect-virt 2>/dev/null || true; "
    "fi; "
    # Full per-disk S.M.A.R.T. detail — bare metal only, see app.ssh.smart.
    f"{SMART_FACTS_SECTION}; "
    # Debian/Ubuntu's own "a reboot is needed" flag (written by package
    # postinst scripts — libc, systemd, microcode, a kernel), on top of
    # the running-vs-installed kernel comparison.
    "echo ===REBOOT_FLAG===; [ -f /run/reboot-required ] && echo yes; "
    # Proxmox VE version, storages and backups — app.ssh.proxmox.
    f"{proxmox.INVENTORY_COMMAND}"
)


class MachineFacts(TypedDict):
    hostname: str | None
    os_version: str | None
    os_id: str | None
    kernel_version: str | None
    cpu_architecture: str | None
    cpu_cores: int | None
    cpu_model: str | None
    ram_bytes: int | None
    # MHz, only when dmidecode was actually readable — see FACTS_COMMAND's
    # RAM_SPEED comment. None means "couldn't tell", not "no RAM".
    ram_speed_mhz: int | None
    disks: list[dict[str, Any]]
    # None means "couldn't tell" (e.g. dpkg unavailable), not "no reboot needed".
    reboot_required: bool | None
    uptime_seconds: int | None
    process_count: int | None
    filesystems: list[dict[str, Any]]
    network_interfaces: list[dict[str, Any]]
    # Sorted, de-duplicated `address:port` of listening TCP sockets
    # (`0.0.0.0:22`, `[::]:443`, `127.0.0.1:5432`); None = `ss` printed
    # nothing at all (not installed), [] never happens in practice.
    listening_ports: list[str] | None
    # Sorted local admin accounts / login accounts — see FACTS_COMMAND.
    admin_users: list[str]
    login_users: list[str]
    # True on bare metal, False inside a VM/container, None if it couldn't
    # be determined at all (no systemd-detect-virt) — see FACTS_COMMAND's
    # own VIRT comment.
    is_physical: bool | None
    # One summary per readable disk (see app.ssh.smart.parse_smart_device);
    # None = not applicable (a VM, or no smartctl), [] = ran, nothing readable.
    smart_devices: list[dict[str, Any]] | None
    # Proxmox VE only (None elsewhere) — see app.ssh.proxmox.
    pve_version: str | None
    pve_storage: list[dict[str, Any]] | None
    pve_backups: dict[str, Any] | None


def _split_sections(raw: str) -> dict[str, str]:
    """{marker name: section text}, keyed by the marker actually found —
    so output missing a section (an older command, a shell that died
    halfway) never shifts every later section onto the wrong name."""
    pattern = "|".join(re.escape(name) for name in _SECTION_MARKERS)
    parts = re.split(f"===({pattern})===", raw)
    # parts = [before-first-marker, name1, body1, name2, body2, ...]
    return {parts[i]: parts[i + 1].strip() for i in range(1, len(parts) - 1, 2)}


def _parse_listening(section: str) -> list[str] | None:
    """`ss -Htln`'s local-address column -> sorted unique `address:port`.
    A zone suffix (`127.0.0.53%lo:53`) is dropped; `*:80` is kept as is."""
    if not section.strip():
        return None
    found: set[str] = set()
    for line in section.splitlines():
        value = line.strip()
        address, sep, port = value.rpartition(":")
        if not sep or not port.isdigit():
            continue
        address = address.split("%", 1)[0] if not address.startswith("[") else address
        found.add(f"{address}:{port}")
    return sorted(found, key=lambda item: (int(item.rpartition(":")[2]), item))


def _sorted_names(section: str) -> list[str]:
    """One account name per line -> sorted unique list."""
    names = {line.strip() for line in section.splitlines() if line.strip()}
    return sorted(names)


def parse_facts_output(raw: str) -> MachineFacts:
    """Parse the output of `FACTS_COMMAND` into structured facts.

    Pure function, no I/O — kept separate from `gather_facts` so the parsing
    logic can be unit-tested against canned output.
    """
    sections = _split_sections(raw)

    cpu_cores: int | None = None
    if sections.get("CPU", "").isdigit():
        cpu_cores = int(sections["CPU"])

    ram_bytes: int | None = None
    if sections.get("RAM_KB", "").isdigit():
        ram_bytes = int(sections["RAM_KB"]) * 1024

    ram_speed_mhz: int | None = None
    if sections.get("RAM_SPEED", "").isdigit():
        ram_speed_mhz = int(sections["RAM_SPEED"])

    disks: list[dict[str, Any]] = []
    for line in sections.get("DISKS", "").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit():
            disks.append({"name": fields[0], "size_bytes": int(fields[1])})

    kernel_version = sections.get("KERNEL") or None
    kernel_latest = sections.get("KERNEL_LATEST") or None
    # A newer kernel *package* than the one actually running means a reboot
    # would pick it up. If we couldn't determine the latest installed
    # kernel at all (e.g. no dpkg, or no linux-image-* packages — some
    # minimal/container images), we simply don't know either way.
    reboot_required: bool | None = None
    if kernel_version and kernel_latest:
        reboot_required = kernel_latest != kernel_version
    if sections.get("REBOOT_FLAG") == "yes":
        reboot_required = True

    uptime_seconds: int | None = None
    if sections.get("UPTIME", "").isdigit():
        uptime_seconds = int(sections["UPTIME"])

    process_count: int | None = None
    if sections.get("PROCESSES", "").isdigit():
        process_count = int(sections["PROCESSES"])

    filesystems: list[dict[str, Any]] = []
    for line in sections.get("FILESYSTEMS", "").splitlines():
        fields = line.split()
        # target size used avail pcent — target can't be reliably split out
        # if it contains spaces (rare for a mount point), so this takes the
        # last four fields as the numbers/percentage and joins the rest.
        if len(fields) < 5:
            continue
        size, used, avail, pcent = fields[-4], fields[-3], fields[-2], fields[-1]
        target = " ".join(fields[:-4])
        if not (size.isdigit() and used.isdigit() and avail.isdigit()):
            continue
        filesystems.append(
            {
                "mount": target,
                "size_bytes": int(size),
                "used_bytes": int(used),
                "avail_bytes": int(avail),
                "use_percent": int(pcent.rstrip("%")) if pcent.rstrip("%").isdigit() else None,
            }
        )

    network_interfaces: list[dict[str, Any]] = []
    for line in sections.get("NETWORK", "").splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        interface, address = fields
        network_interfaces.append({"interface": interface.rstrip(":"), "address": address})

    listening_ports = _parse_listening(sections.get("LISTEN", ""))
    admin_users = _sorted_names(sections.get("ADMINS", ""))
    login_users = _sorted_names(sections.get("LOGINS", ""))

    virt_raw = sections.get("VIRT", "").strip().lower()
    is_physical: bool | None = None
    if virt_raw:
        is_physical = virt_raw == "none"

    return MachineFacts(
        hostname=sections.get("HOSTNAME") or None,
        os_version=sections.get("OS") or None,
        os_id=(sections.get("OS_ID") or "").lower() or None,
        kernel_version=kernel_version,
        cpu_architecture=sections.get("ARCH") or None,
        cpu_cores=cpu_cores,
        cpu_model=sections.get("CPU_MODEL") or None,
        ram_bytes=ram_bytes,
        ram_speed_mhz=ram_speed_mhz,
        disks=disks,
        reboot_required=reboot_required,
        uptime_seconds=uptime_seconds,
        process_count=process_count,
        filesystems=filesystems,
        network_interfaces=network_interfaces,
        listening_ports=listening_ports,
        admin_users=admin_users,
        login_users=login_users,
        is_physical=is_physical,
        smart_devices=parse_smart_section(sections.get("SMART", "")),
        pve_version=proxmox.parse_pve_version(sections.get("PVE_VERSION", "")),
        pve_storage=proxmox.parse_storage(sections.get("PVE_STORAGE", "")),
        pve_backups=proxmox.parse_backups(
            sections.get("PVE_BACKUP_TASKS", ""),
            sections.get("PVE_BACKUP_JOBS", ""),
            sections.get("PVE_NOT_BACKED_UP", ""),
        ),
    )


async def gather_facts(machine: Machine, secret: str | None, timeout_seconds: int) -> MachineFacts:
    """Connect to a machine and gather its facts. Requires a pinned host key."""
    async with machine_connection(machine, secret, timeout_seconds) as conn:
        # smartctl -a reads each disk's logs — allow for a few slow disks.
        result = await conn.run(
            with_root_shim(FACTS_COMMAND), check=False, timeout=timeout_seconds + 30
        )

    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_facts_output(raw)


# Just the three sections `reboot_required` is computed from — run after an
# update, to decide whether "reboot only if needed" should reboot.
REBOOT_CHECK_COMMAND = (
    "echo ===KERNEL===; uname -r 2>/dev/null; "
    "echo ===KERNEL_LATEST===; "
    "dpkg --list 'linux-image-*' 'proxmox-kernel-*' 'pve-kernel-*' 2>/dev/null "
    "| awk '/^ii/{print $2}' "
    "| sed -E 's/^(linux-image|proxmox-kernel|pve-kernel)-//; s/-signed$//' "
    "| grep -E '^[0-9]' | sort -V | tail -1; "
    "echo ===REBOOT_FLAG===; [ -f /run/reboot-required ] && echo yes; true"
)


async def check_reboot_required(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> bool | None:
    """Whether `machine` needs a reboot right now (newer kernel installed
    than running, or Debian's /run/reboot-required flag); None = couldn't
    tell."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(REBOOT_CHECK_COMMAND, check=False, timeout=timeout_seconds + 15)
    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_facts_output(raw)["reboot_required"]
