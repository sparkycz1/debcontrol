"""Run (or just check for) system updates on a machine: apt, plus flatpak
and snap when either is present.

`run_system_update`: always the same shape — `apt-get update`, then the
chosen upgrade strategy, then `autoremove` and `autoclean`, then (if
installed) `flatpak update` and `snap refresh` — the cleanup and flatpak/
snap steps run unconditionally, even if the apt upgrade step failed, since
they're independently useful and shouldn't be skipped just because apt hit
a problem. Overall success/failure is still judged by the apt step alone
(unchanged from before flatpak/snap support), since that's the one debcontrol
can meaningfully retry or diagnose — flatpak/snap failures still show up in
the stored output for the admin to read.

`check_updates`: a read-only dry run — refreshes the apt cache and reports
how many packages are upgradable (and how many of those are from a
`*-security` suite), plus how many flatpak and snap packages have pending
updates, without installing or upgrading anything.

apt requires root — either the machine's configured username *is* root, or
(recommended) it has passwordless sudo for `apt-get` specifically. See the
wiki page "Managed Machine Requirements" for a sudoers example. `sudo -n`
(non-interactive) is used throughout: if sudo would need a password, the
command fails immediately with a clear error instead of hanging forever
waiting for input that can never arrive over a non-interactive SSH exec.
flatpak/snap are also run via `sudo -n` for consistency (system-wide
flatpak/snap operations commonly need it too) — see the sudoers example in
the wiki page, which covers all three.

Neither flatpak nor snap is required to be installed: every step here is
guarded with `command -v`, so a machine without one (or both) simply skips
that part rather than failing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.db.models.machine import Machine
from app.db.models.machine_update_run import UpgradeStrategy
from app.ssh.client import open_connection

_SUDO_APT = "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -y -q"
# Never prompt on a config-file conflict — keep the admin's existing config.
# The standard safe default for unattended Debian upgrades.
_DPKG_NONINTERACTIVE_FLAGS = (
    "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
)
_UPGRADE_SUBCOMMAND = {
    UpgradeStrategy.DIST_UPGRADE: "dist-upgrade",
    UpgradeStrategy.FULL_UPGRADE: "full-upgrade",
}


def build_update_command(strategy: UpgradeStrategy) -> str:
    """Build the remote shell script for one update run.

    A brace group (`{ ...; }`) rather than separate exec calls, so `2>&1`
    at the end captures stdout+stderr from every step in one place, and so
    the cleanup steps can run unconditionally while still preserving the
    upgrade step's exit status as the overall result.
    """
    upgrade_subcommand = _UPGRADE_SUBCOMMAND[strategy]
    return (
        "{ "
        "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update -q; "
        'status=$?; '
        'if [ "$status" -eq 0 ]; then '
        f"{_SUDO_APT} {_DPKG_NONINTERACTIVE_FLAGS} {upgrade_subcommand}; "
        'status=$?; '
        "fi; "
        f"{_SUDO_APT} autoremove; "
        f"{_SUDO_APT} autoclean; "
        "if command -v flatpak >/dev/null 2>&1; then "
        "sudo -n flatpak update -y --noninteractive; "
        "fi; "
        "if command -v snap >/dev/null 2>&1; then sudo -n snap refresh; fi; "
        'exit "$status"; '
        "} 2>&1"
    )


@dataclass
class UpdateResult:
    exit_status: int
    output: str


async def run_system_update(
    machine: Machine,
    secret: str | None,
    strategy: UpgradeStrategy,
    connect_timeout_seconds: int,
    run_timeout_seconds: int,
) -> UpdateResult:
    """Connect (strict pinned host-key verification, as always) and run the
    update sequence. `connect_timeout_seconds` only bounds establishing the
    connection; `run_timeout_seconds` bounds the whole apt sequence, which
    can legitimately take much longer.
    """
    script = build_update_command(strategy)
    async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
        result = await conn.run(script, check=False, timeout=run_timeout_seconds)

    stdout = result.stdout or ""
    output = stdout if isinstance(stdout, str) else stdout.decode()
    exit_status = result.exit_status if result.exit_status is not None else -1
    return UpdateResult(exit_status=exit_status, output=output)


_APT_MARKER = "===APT_UPGRADABLE==="
_FLATPAK_MARKER = "===FLATPAK_UPGRADABLE==="
_SNAP_MARKER = "===SNAP_UPGRADABLE==="
_CHECK_SECTION_MARKERS = ("APT_UPGRADABLE", "FLATPAK_UPGRADABLE", "SNAP_UPGRADABLE")

# Refreshes the apt package lists (needs root, same as an actual upgrade)
# and then lists what's upgradable across all three sources — apt doesn't
# need root once the cache is refreshed, and flatpak/snap listing never
# does. The apt section only runs if the refresh succeeded, so a stale/
# absent cache never gets reported as "0 updates". flatpak/snap are each
# guarded with `command -v`, since neither is required to be installed:
#   - flatpak: `flatpak remote-ls --updates` per configured remote is the
#     genuine dry-run equivalent — it lists what a remote has that differs
#     from what's deployed, without touching anything.
#   - snap: `snap refresh --list` is snapd's own official dry-run listing
#     of pending refreshes, and (unlike applying them) doesn't need root.
_CHECK_UPDATES_COMMAND = (
    "{ "
    "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null; "
    'status=$?; '
    f"echo {_APT_MARKER}; "
    'if [ "$status" -eq 0 ]; then apt list --upgradable 2>/dev/null | tail -n +2; fi; '
    f"echo {_FLATPAK_MARKER}; "
    "if command -v flatpak >/dev/null 2>&1; then "
    "for r in $(flatpak remotes --columns=name 2>/dev/null); do "
    'flatpak remote-ls --updates --columns=application "$r" 2>/dev/null; '
    "done; "
    "fi; "
    f"echo {_SNAP_MARKER}; "
    "if command -v snap >/dev/null 2>&1; then "
    "snap refresh --list 2>/dev/null | tail -n +2 | awk '{print $1}'; "
    "fi; "
    'exit "$status"; '
    "} 2>&1"
)


def _split_check_sections(raw: str) -> dict[str, str]:
    pattern = "|".join(f"==={name}===" for name in _CHECK_SECTION_MARKERS)
    parts = re.split(f"(?:{pattern})", raw)
    body = parts[1:]
    return dict(zip(_CHECK_SECTION_MARKERS, (chunk.strip() for chunk in body), strict=False))


def parse_upgradable_output(raw: str) -> tuple[int, int]:
    """Count upgradable / security-upgradable apt packages from the
    `APT_UPGRADABLE` section of `_CHECK_UPDATES_COMMAND`'s output — each
    line looks like `pkgname/suite version arch [upgradable from: ...]`.

    Pure function, no I/O — kept separate from `check_updates` so the
    parsing logic can be unit-tested against canned output.
    """
    tail = _split_check_sections(raw).get("APT_UPGRADABLE", "")
    lines = [line for line in tail.splitlines() if line.strip()]

    security_count = 0
    for line in lines:
        first_token = line.split(" ", 1)[0]  # "pkgname/suite"
        suite = first_token.partition("/")[2]
        if "security" in suite:
            security_count += 1

    return len(lines), security_count


def parse_flatpak_upgradable_output(raw: str) -> int:
    """Count pending flatpak updates from the `FLATPAK_UPGRADABLE` section
    — one application id per line. `flatpak remote-ls --updates` is run
    once per configured remote, so the same app could in principle appear
    twice (tracked from two remotes) — de-duplicated here."""
    tail = _split_check_sections(raw).get("FLATPAK_UPGRADABLE", "")
    apps = {line.strip() for line in tail.splitlines() if line.strip()}
    return len(apps)


def parse_snap_upgradable_output(raw: str) -> int:
    """Count pending snap refreshes from the `SNAP_UPGRADABLE` section —
    one snap name per line."""
    tail = _split_check_sections(raw).get("SNAP_UPGRADABLE", "")
    return len([line for line in tail.splitlines() if line.strip()])


@dataclass
class UpdateCheckResult:
    exit_status: int
    upgradable_count: int
    security_upgradable_count: int
    flatpak_upgradable_count: int
    snap_upgradable_count: int
    output: str


async def check_updates(
    machine: Machine,
    secret: str | None,
    connect_timeout_seconds: int,
    run_timeout_seconds: int,
) -> UpdateCheckResult:
    """Refresh the apt cache and report how many packages/apps/snaps are
    upgradable across apt, flatpak, and snap, without installing or
    upgrading anything. Same root/sudo requirement as `run_system_update`
    — see the module docstring.
    """
    async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
        result = await conn.run(_CHECK_UPDATES_COMMAND, check=False, timeout=run_timeout_seconds)

    stdout = result.stdout or ""
    output = stdout if isinstance(stdout, str) else stdout.decode()
    exit_status = result.exit_status if result.exit_status is not None else -1
    upgradable_count, security_upgradable_count = parse_upgradable_output(output)
    return UpdateCheckResult(
        exit_status=exit_status,
        upgradable_count=upgradable_count,
        security_upgradable_count=security_upgradable_count,
        flatpak_upgradable_count=parse_flatpak_upgradable_output(output),
        snap_upgradable_count=parse_snap_upgradable_output(output),
        output=output,
    )
