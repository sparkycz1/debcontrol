"""Post-onboarding readiness check — did the app's own setup requirements
(`ncurses-term`, and this account's scoped sudo for apt/shutdown/
dmidecode/flatpak+snap — see `app.ssh.onboarding.build_onboarding_command`)
actually take, or did installing/granting one of them fail or get skipped
(no network at onboarding time, a hand-onboarded machine that predates one
of these requirements, ...)? Read-only: every check here is a plain
`dpkg -s`/`sudo -n ... --version`-style probe — nothing is installed or
changed by running this.
"""

from __future__ import annotations

import re
from typing import TypedDict

from app.db.models.machine import Machine
from app.ssh.client import open_connection

_SECTION_MARKERS = (
    "NCURSES_TERM",
    "APT_SUDO",
    "SHUTDOWN_SUDO",
    "DMIDECODE_SUDO",
    "FLATPAK_SNAP_PRESENT",
    "FLATPAK_SNAP_SUDO",
)

READINESS_COMMAND = (
    "echo ===NCURSES_TERM===; "
    "dpkg -s ncurses-term >/dev/null 2>&1 && echo ok || echo missing; "
    "echo ===APT_SUDO===; "
    "sudo -n apt-get --version >/dev/null 2>&1 && echo ok || echo missing; "
    "echo ===SHUTDOWN_SUDO===; "
    "sudo -n shutdown --help >/dev/null 2>&1 && echo ok || echo missing; "
    "echo ===DMIDECODE_SUDO===; "
    "sudo -n dmidecode -t 17 >/dev/null 2>&1 && echo ok || echo missing; "
    "echo ===FLATPAK_SNAP_PRESENT===; "
    "(command -v flatpak >/dev/null 2>&1 || command -v snap >/dev/null 2>&1) "
    "&& echo yes || echo no; "
    "echo ===FLATPAK_SNAP_SUDO===; "
    "ok=1; "
    "if command -v flatpak >/dev/null 2>&1; then "
    "sudo -n flatpak --version >/dev/null 2>&1 || ok=0; fi; "
    "if command -v snap >/dev/null 2>&1; then "
    "sudo -n snap version >/dev/null 2>&1 || ok=0; fi; "
    '[ "$ok" = 1 ] && echo ok || echo missing'
)


class ReadinessResult(TypedDict):
    ncurses_term_installed: bool
    apt_sudo_ok: bool
    shutdown_sudo_ok: bool
    dmidecode_sudo_ok: bool
    flatpak_or_snap_present: bool
    flatpak_snap_sudo_ok: bool


def _split_sections(raw: str) -> dict[str, str]:
    pattern = "|".join(f"==={name}===" for name in _SECTION_MARKERS)
    parts = re.split(f"(?:{pattern})", raw)
    body = parts[1:]
    return dict(zip(_SECTION_MARKERS, (chunk.strip() for chunk in body), strict=False))


def parse_readiness_output(raw: str) -> ReadinessResult:
    """Parse `READINESS_COMMAND`'s output. Pure function, no I/O. A section
    that's missing or unrecognized reads as "not ok" — a dropped connection
    partway through should look like problems remain, never like
    everything's fine."""
    sections = _split_sections(raw)
    return ReadinessResult(
        ncurses_term_installed=sections.get("NCURSES_TERM") == "ok",
        apt_sudo_ok=sections.get("APT_SUDO") == "ok",
        shutdown_sudo_ok=sections.get("SHUTDOWN_SUDO") == "ok",
        dmidecode_sudo_ok=sections.get("DMIDECODE_SUDO") == "ok",
        flatpak_or_snap_present=sections.get("FLATPAK_SNAP_PRESENT") == "yes",
        flatpak_snap_sudo_ok=sections.get("FLATPAK_SNAP_SUDO") == "ok",
    )


# (result key, human-readable description) — checked in this order so the
# banner's list reads roughly most-to-least impactful.
_REQUIREMENT_LABELS: tuple[tuple[str, str], ...] = (
    ("apt_sudo_ok", "passwordless sudo for apt-get (needed for checking/running updates)"),
    ("shutdown_sudo_ok", "passwordless sudo for shutdown (needed for reboot/power actions)"),
    ("dmidecode_sudo_ok", "passwordless sudo for dmidecode (needed for the RAM speed fact)"),
    ("ncurses_term_installed", "ncurses-term (needed for full-color terminal output)"),
)


def missing_requirements(result: ReadinessResult) -> list[str]:
    """Human-readable descriptions of whatever `result` says isn't set up
    — empty means everything checked is in place. `flatpak_snap_sudo_ok`
    is only reported when flatpak or snap is actually present (no point
    telling an operator to fix sudo for a package manager the machine
    doesn't even have)."""
    missing = [label for key, label in _REQUIREMENT_LABELS if not result[key]]  # type: ignore[literal-required]
    if result["flatpak_or_snap_present"] and not result["flatpak_snap_sudo_ok"]:
        missing.append("passwordless sudo for flatpak/snap (needed for those updates)")
    return missing


async def check_machine_readiness(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> ReadinessResult:
    """Connect to a machine and run every readiness probe. Requires a
    pinned host key."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(READINESS_COMMAND, check=False, timeout=timeout_seconds)
    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_readiness_output(raw)
