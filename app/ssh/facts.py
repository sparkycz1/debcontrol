"""Gather basic facts about a managed machine over SSH.

Deliberately uses only tools present on a stock Debian install (coreutils,
util-linux, dpkg, base-files) — no agent, no extra packages required on
the target, and nothing here needs root. See the wiki page "Managed
Machine Requirements".
"""

from __future__ import annotations

import re
from typing import Any, TypedDict

from app.db.models.machine import Machine
from app.ssh.client import open_connection

_SECTION_MARKERS = ("HOSTNAME", "OS", "KERNEL", "KERNEL_LATEST", "CPU", "RAM_KB", "DISKS")

# One round trip: each section is delimited by a "===NAME===" marker so the
# output can be split reliably even if a command prints nothing or errors.
FACTS_COMMAND = (
    "echo ===HOSTNAME===; hostname 2>/dev/null; "
    "echo ===OS===; "
    "(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"'); "
    "echo ===KERNEL===; uname -r 2>/dev/null; "
    "echo ===KERNEL_LATEST===; "
    "dpkg --list 'linux-image-*' 2>/dev/null | awk '/^ii/{print $2}' "
    "| sed -E 's/^linux-image-//' | grep -E '^[0-9]' | sort -V | tail -1; "
    "echo ===CPU===; nproc 2>/dev/null; "
    "echo ===RAM_KB===; awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null; "
    "echo ===DISKS===; "
    "lsblk -b -d -n -o NAME,SIZE,TYPE 2>/dev/null | awk '$3==\"disk\"{print $1, $2}'"
)


class MachineFacts(TypedDict):
    hostname: str | None
    os_version: str | None
    kernel_version: str | None
    cpu_cores: int | None
    ram_bytes: int | None
    disks: list[dict[str, Any]]
    # None means "couldn't tell" (e.g. dpkg unavailable), not "no reboot needed".
    reboot_required: bool | None


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

    return MachineFacts(
        hostname=sections.get("HOSTNAME") or None,
        os_version=sections.get("OS") or None,
        kernel_version=kernel_version,
        cpu_cores=cpu_cores,
        ram_bytes=ram_bytes,
        disks=disks,
        reboot_required=reboot_required,
    )


async def gather_facts(machine: Machine, secret: str | None, timeout_seconds: int) -> MachineFacts:
    """Connect to a machine and gather its facts. Requires a pinned host key."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(FACTS_COMMAND, check=False, timeout=timeout_seconds)

    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_facts_output(raw)
