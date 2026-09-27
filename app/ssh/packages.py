"""List installed packages on a managed machine — apt (dpkg), plus flatpak
and snap when either is present. Read-only, no root needed for any of it.

See the wiki page "Machine Requirements" for exactly which tools
are used and why none of them need elevated privileges.
"""

from __future__ import annotations

import enum
import re
from typing import TypedDict

from app.db.models.machine import Machine
from app.ssh.pool import machine_connection
from app.ssh.shell import with_root_shim

_SECTION_MARKERS = ("APT", "FLATPAK", "SNAP", "HELD")

# One round trip, same "===NAME===" marker trick as app.ssh.facts. flatpak
# and snap are optional — most Debian/Ubuntu installs don't have either by
# default — so each is guarded with `command -v` and simply produces an
# empty section (not an error) when absent. `apt-mark showhold` never needs
# root either — it just reads dpkg's selection state, same as `dpkg-query`.
PACKAGES_COMMAND = (
    "echo ===APT===; "
    "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null; "
    "echo ===FLATPAK===; "
    "if command -v flatpak >/dev/null 2>&1; then "
    "flatpak list --app --columns=application,version 2>/dev/null; "
    "fi; "
    "echo ===SNAP===; "
    "if command -v snap >/dev/null 2>&1; then "
    "snap list 2>/dev/null | tail -n +2 | awk '{print $1\"\\t\"$2}'; "
    "fi; "
    "echo ===HELD===; "
    "apt-mark showhold 2>/dev/null"
)


class PackageSource(enum.StrEnum):
    APT = "apt"
    FLATPAK = "flatpak"
    SNAP = "snap"


class PackageEntry(TypedDict):
    source: PackageSource
    name: str
    version: str
    # Only ever True for an APT entry — `apt-mark showhold` has no flatpak/
    # snap equivalent, and neither package manager has this concept.
    held: bool


def _split_sections(raw: str) -> dict[str, str]:
    pattern = "|".join(f"==={name}===" for name in _SECTION_MARKERS)
    parts = re.split(f"(?:{pattern})", raw)
    body = parts[1:]
    return dict(zip(_SECTION_MARKERS, (chunk.strip() for chunk in body), strict=False))


def _parse_tab_separated(
    chunk: str, source: PackageSource, *, held_names: frozenset[str] = frozenset()
) -> list[PackageEntry]:
    entries: list[PackageEntry] = []
    for line in chunk.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        name, version = fields[0].strip(), fields[1].strip()
        if not name:
            continue
        entries.append(
            PackageEntry(source=source, name=name, version=version, held=name in held_names)
        )
    return entries


def parse_packages_output(raw: str) -> list[PackageEntry]:
    """Parse the output of `PACKAGES_COMMAND` into a flat list of packages.

    Pure function, no I/O — kept separate from `gather_packages` so the
    parsing logic can be unit-tested against canned output.
    """
    sections = _split_sections(raw)
    held_names = frozenset(
        line.strip() for line in sections.get("HELD", "").splitlines() if line.strip()
    )

    entries: list[PackageEntry] = []
    entries += _parse_tab_separated(
        sections.get("APT", ""), PackageSource.APT, held_names=held_names
    )
    entries += _parse_tab_separated(sections.get("FLATPAK", ""), PackageSource.FLATPAK)
    entries += _parse_tab_separated(sections.get("SNAP", ""), PackageSource.SNAP)
    return entries


async def gather_packages(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> list[PackageEntry]:
    """Connect to a machine and list its installed packages. Requires a
    pinned host key."""
    async with machine_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(
            with_root_shim(PACKAGES_COMMAND), check=False, timeout=timeout_seconds
        )

    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_packages_output(raw)
