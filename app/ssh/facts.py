"""Gather basic facts about a managed machine over SSH.

Deliberately uses only tools present on a stock Debian install (coreutils,
util-linux, dpkg, base-files, iproute2) — no agent, no extra packages
required on the target, and nothing here needs root. See the wiki page
"Managed Machine Requirements".
"""

from __future__ import annotations

import re
from typing import Any, TypedDict

from app.db.models.machine import Machine
from app.ssh.client import open_connection

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
    "echo ===KERNEL_LATEST===; "
    "dpkg --list 'linux-image-*' 2>/dev/null | awk '/^ii/{print $2}' "
    "| sed -E 's/^linux-image-//' | grep -E '^[0-9]' | sort -V | tail -1; "
    "echo ===ARCH===; uname -m 2>/dev/null; "
    "echo ===CPU===; nproc 2>/dev/null; "
    "echo ===CPU_MODEL===; "
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
    "ip -4 -o addr show scope global 2>/dev/null | awk '{print $2, $4}'"
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


def _split_sections(raw: str) -> dict[str, str]:
    pattern = "|".join(f"==={name}===" for name in _SECTION_MARKERS)
    parts = re.split(f"(?:{pattern})", raw)
    # The first chunk (before the first marker) is discarded; what remains
    # lines up 1:1 with _SECTION_MARKERS, in the order the command emits them.
    body = parts[1:]
    return dict(zip(_SECTION_MARKERS, (chunk.strip() for chunk in body), strict=False))


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
    )


async def gather_facts(machine: Machine, secret: str | None, timeout_seconds: int) -> MachineFacts:
    """Connect to a machine and gather its facts. Requires a pinned host key."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(FACTS_COMMAND, check=False, timeout=timeout_seconds)

    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_facts_output(raw)
