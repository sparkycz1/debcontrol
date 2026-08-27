"""Gather basic facts about a managed machine over SSH.

Deliberately uses only tools present on a stock Debian install (coreutils,
util-linux, base-files) — no agent, no extra packages required on the
target. See the wiki page "Managed Machine Requirements".
"""

from __future__ import annotations

import re
from typing import Any, TypedDict

from app.db.models.machine import Machine
from app.ssh.client import open_connection

_SECTION_MARKERS = ("HOSTNAME", "OS", "KERNEL", "CPU", "RAM_KB", "DISKS")

# One round trip: each section is delimited by a "===NAME===" marker so the
# output can be split reliably even if a command prints nothing or errors.
FACTS_COMMAND = (
    "echo ===HOSTNAME===; hostname 2>/dev/null; "
    "echo ===OS===; "
    "(grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '\"'); "
    "echo ===KERNEL===; uname -r 2>/dev/null; "
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

    return MachineFacts(
        hostname=sections.get("HOSTNAME") or None,
        os_version=sections.get("OS") or None,
        kernel_version=sections.get("KERNEL") or None,
        cpu_cores=cpu_cores,
        ram_bytes=ram_bytes,
        disks=disks,
    )


async def gather_facts(machine: Machine, secret: str | None, timeout_seconds: int) -> MachineFacts:
    """Connect to a machine and gather its facts. Requires a pinned host key."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(FACTS_COMMAND, check=False, timeout=timeout_seconds)

    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_facts_output(raw)
