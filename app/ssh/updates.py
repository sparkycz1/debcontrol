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
wiki page "Machine Requirements" for a sudoers example. `sudo -n`
(non-interactive) is used throughout: if sudo would need a password, the
command fails immediately with a clear error instead of hanging forever
waiting for input that can never arrive over a non-interactive SSH exec.
flatpak/snap are also run via `sudo -n` for consistency (system-wide
flatpak/snap operations commonly need it too) — see the sudoers example in
the wiki page, which covers all three.

Every privileged step is wrapped by `_with_root_fallback`: try it via
`sudo -n` first, and if that fails (no sudo grant — or no `sudo` binary at
all on a minimal root-only image), run it directly instead. That fallback
only ever matters when the connecting account is already root (an
unprivileged fallback just fails again with its own permission-denied
error, no different from today) — see `app.ssh.facts`'s `dmidecode` probe
for the same idiom, and `app.ssh.readiness` for why root should never be
asked to grant itself sudo in the first place.

Neither flatpak nor snap is required to be installed: every step here is
guarded with `command -v`, so a machine without one (or both) simply skips
that part rather than failing.
"""

from __future__ import annotations

import asyncio
import re
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import NotRequired, TypedDict

import asyncssh

from app.db.models.machine import Machine
from app.db.models.machine_update_run import UpgradeStrategy
from app.ssh.client import open_connection
from app.ssh.pool import machine_connection
from app.ssh.security_advisories import is_safe_package_name, lookup_advisories
from app.ssh.shell import with_root_shim


class PendingPackage(TypedDict):
    name: str
    current_version: str | None
    # Available/new version — always known, since that's what "there's an
    # update" means. `None` only for a source where a listing command
    # genuinely doesn't report it (kept for symmetry, unused today).
    new_version: str | None
    # apt only: from a `*-security` suite. Absent on flatpak/snap entries
    # and on lists stored before debcontrol tracked it.
    security: NotRequired[bool]
    # apt security updates only: the CVE ids the update fixes and the
    # highest changelog urgency (see app.ssh.security_advisories); absent
    # or None = not looked up (yet).
    cves: NotRequired[list[str] | None]
    urgency: NotRequired[str | None]

def _with_root_fallback(command: str) -> str:
    """`command`, run via passwordless sudo, or run directly if sudo isn't
    there/configured for it — see the module docstring. `2>/dev/null` on
    the sudo attempt only, so a real failure from the fallback (whichever
    account actually ran it) still shows up in the captured output instead
    of being masked by sudo's own "a password is required" noise."""
    return f"(sudo -n {command} 2>/dev/null || {command})"


_APT_BASE = "env DEBIAN_FRONTEND=noninteractive apt-get -y -q"
# Never prompt on a config-file conflict — keep the admin's existing config.
# The standard safe default for unattended Debian upgrades.
_DPKG_NONINTERACTIVE_FLAGS = (
    "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
)
_UPGRADE_SUBCOMMAND = {
    UpgradeStrategy.DIST_UPGRADE: "dist-upgrade",
    UpgradeStrategy.FULL_UPGRADE: "full-upgrade",
    UpgradeStrategy.UPGRADE: "upgrade",
}

# Packages with a pending update from a `*-security` suite, as apt's own
# simulated upgrade reports them (the `Inst` line names the suite:
# `(1.2-3 Debian-Security:12/stable-security [amd64])`, Ubuntu's
# `jammy-security`). Collected into `$pkgs` for `_upgrade_step`.
_SECURITY_PACKAGES = (
    'pkgs="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null '
    "| awk '/^Inst / && tolower($0) ~ /-security/ {print $2}' | sort -u | tr '\\n' ' ')\"; "
)


def _apt(args: str) -> str:
    return _with_root_fallback(f"{_APT_BASE} {args}")


# `apt-get update`'s own stdout is only ever wanted once, for a real update
# run — `_CHECK_UPDATES_COMMAND` and the preview below only care about the
# refresh's exit status, so they use the `>/dev/null` variant instead.
_APT_REFRESH = _with_root_fallback("env DEBIAN_FRONTEND=noninteractive apt-get update -q")
_APT_REFRESH_QUIET = _with_root_fallback(
    "env DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null"
)


def _upgrade_step(strategy: UpgradeStrategy, *, simulate: bool = False) -> str:
    """The upgrade itself for `strategy` — `apt-get <subcommand>`, or for
    `security` an `install --only-upgrade` of just the security packages
    (nothing to do → a message, exit status 0). `simulate` adds `-s`."""
    # Simulating needs no dpkg conffile options — nothing gets configured.
    options = "-s" if simulate else _DPKG_NONINTERACTIVE_FLAGS
    if strategy == UpgradeStrategy.SECURITY:
        return (
            f"{_SECURITY_PACKAGES}"
            'if [ -n "$pkgs" ]; then '
            f"{_apt(f'{options} install --only-upgrade $pkgs')}; "
            "else echo 'No pending security updates.'; fi"
        )
    return _apt(f"{options} {_UPGRADE_SUBCOMMAND[strategy]}")


def build_update_command(strategy: UpgradeStrategy) -> str:
    """Build the remote shell script for one update run.

    A brace group (`{ ...; }`) rather than separate exec calls, so `2>&1`
    at the end captures stdout+stderr from every step in one place, and so
    the cleanup steps can run unconditionally while still preserving the
    upgrade step's exit status as the overall result.
    """
    return (
        "{ "
        f"{_APT_REFRESH}; "
        'status=$?; '
        'if [ "$status" -eq 0 ]; then '
        f"{_upgrade_step(strategy)}; "
        'status=$?; '
        "fi; "
        f"{_apt('autoremove')}; "
        f"{_apt('autoclean')}; "
        "if command -v flatpak >/dev/null 2>&1; then "
        f"{_with_root_fallback('flatpak update -y --noninteractive')}; "
        "fi; "
        "if command -v snap >/dev/null 2>&1; then "
        f"{_with_root_fallback('snap refresh')}; fi; "
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
    *,
    on_output: Callable[[str], Awaitable[None]] | None = None,
) -> UpdateResult:
    """Connect (strict pinned host-key verification, as always) and run the
    update sequence. `connect_timeout_seconds` only bounds establishing the
    connection; `run_timeout_seconds` bounds the whole apt sequence, which
    can legitimately take much longer.

    Reads stdout incrementally (rather than `conn.run()`'s buffer-it-all-and-
    return-at-the-end convenience) so `on_output`, if given, can be called
    with the output accumulated *so far* as it arrives — this is what lets
    the update-run page show apt's output live instead of only once the
    whole thing has finished. See `app.tasks.jobs._run_machine_update`,
    the only caller, for what it does with each call (a throttled DB write).
    """
    script = build_update_command(strategy)
    chunks: list[str] = []
    async with (
        await open_connection(machine, secret, connect_timeout_seconds) as conn,
        await conn.create_process(with_root_shim(script), stderr=asyncssh.STDOUT) as process,
    ):
        async with asyncio.timeout(run_timeout_seconds):
            while True:
                chunk = await process.stdout.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if on_output is not None:
                    await on_output("".join(chunks))
        completed = await process.wait()

    output = "".join(chunks)
    exit_status = completed.exit_status if completed.exit_status is not None else -1
    return UpdateResult(exit_status=exit_status, output=output)


_APT_MARKER = "===APT_UPGRADABLE==="
_FLATPAK_MARKER = "===FLATPAK_UPGRADABLE==="
_SNAP_MARKER = "===SNAP_UPGRADABLE==="
_HELD_MARKER = "===APT_HELD==="
_CHECK_SECTION_MARKERS = ("APT_UPGRADABLE", "FLATPAK_UPGRADABLE", "SNAP_UPGRADABLE", "APT_HELD")

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
    f"{_APT_REFRESH_QUIET}; "
    'status=$?; '
    f"echo {_APT_MARKER}; "
    'if [ "$status" -eq 0 ]; then apt list --upgradable 2>/dev/null | tail -n +2; fi; '
    f"echo {_FLATPAK_MARKER}; "
    "if command -v flatpak >/dev/null 2>&1; then "
    "for r in $(flatpak remotes --columns=name 2>/dev/null); do "
    'flatpak remote-ls --updates --columns=application,version "$r" 2>/dev/null; '
    "done; "
    "fi; "
    f"echo {_SNAP_MARKER}; "
    "if command -v snap >/dev/null 2>&1; then "
    "snap refresh --list 2>/dev/null | tail -n +2 | awk '{print $1\"\\t\"$2}'; "
    "fi; "
    # Packages pinned with `apt-mark hold` — never upgraded until released.
    f"echo {_HELD_MARKER}; "
    "apt-mark showhold 2>/dev/null; "
    'exit "$status"; '
    "} 2>&1"
)


def _split_sections(raw: str, markers: tuple[str, ...]) -> dict[str, str]:
    pattern = "|".join(f"==={name}===" for name in markers)
    parts = re.split(f"(?:{pattern})", raw)
    body = parts[1:]
    return dict(zip(markers, (chunk.strip() for chunk in body), strict=False))


def _split_check_sections(raw: str) -> dict[str, str]:
    return _split_sections(raw, _CHECK_SECTION_MARKERS)


_UPGRADABLE_FROM_RE = re.compile(r"\[upgradable from:\s*([^\]]+)\]")


def parse_apt_upgradable_packages(raw: str) -> list[PendingPackage]:
    """List upgradable apt packages, with current/new version, from the
    `APT_UPGRADABLE` section of `_CHECK_UPDATES_COMMAND`'s output — each
    line looks like `pkgname/suite version arch [upgradable from: ...]`.

    Pure function, no I/O — kept separate from `check_updates` so the
    parsing logic can be unit-tested against canned output.
    """
    tail = _split_check_sections(raw).get("APT_UPGRADABLE", "")
    packages: list[PendingPackage] = []
    for line in tail.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split(" ")
        first_token = fields[0]  # "pkgname/suite"
        name = first_token.partition("/")[0]
        new_version = fields[1] if len(fields) > 1 else None
        match = _UPGRADABLE_FROM_RE.search(line)
        current_version = match.group(1).strip() if match else None
        packages.append(
            PendingPackage(
                name=name,
                current_version=current_version,
                new_version=new_version,
                security="security" in first_token.partition("/")[2],
            )
        )
    return packages


def parse_upgradable_output(raw: str) -> tuple[int, int]:
    """Count upgradable / security-upgradable apt packages — a suite
    containing "security" (e.g. `bookworm-security`) counts as a security
    update. Built on `parse_apt_upgradable_packages` plus the raw suite
    names, which that function doesn't keep."""
    tail = _split_check_sections(raw).get("APT_UPGRADABLE", "")
    lines = [line for line in tail.splitlines() if line.strip()]

    security_count = 0
    for line in lines:
        first_token = line.split(" ", 1)[0]  # "pkgname/suite"
        suite = first_token.partition("/")[2]
        if "security" in suite:
            security_count += 1

    return len(lines), security_count


def parse_flatpak_upgradable_packages(raw: str) -> list[PendingPackage]:
    """List pending flatpak updates, with the available version, from the
    `FLATPAK_UPGRADABLE` section — tab-separated `application\tversion`
    per line. `flatpak remote-ls --updates` is run once per configured
    remote, so the same app could in principle appear twice (tracked from
    two remotes) — de-duplicated by application id here."""
    tail = _split_check_sections(raw).get("FLATPAK_UPGRADABLE", "")
    seen: dict[str, PendingPackage] = {}
    for line in tail.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split("\t")
        name = fields[0].strip()
        if not name or name in seen:
            continue
        new_version = fields[1].strip() if len(fields) > 1 and fields[1].strip() else None
        seen[name] = PendingPackage(name=name, current_version=None, new_version=new_version)
    return list(seen.values())


def parse_flatpak_upgradable_output(raw: str) -> int:
    """Count pending flatpak updates — see `parse_flatpak_upgradable_packages`."""
    return len(parse_flatpak_upgradable_packages(raw))


def parse_snap_upgradable_packages(raw: str) -> list[PendingPackage]:
    """List pending snap refreshes, with the available version, from the
    `SNAP_UPGRADABLE` section — tab-separated `name\tversion` per line."""
    tail = _split_check_sections(raw).get("SNAP_UPGRADABLE", "")
    packages: list[PendingPackage] = []
    for line in tail.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split("\t")
        name = fields[0].strip()
        if not name:
            continue
        new_version = fields[1].strip() if len(fields) > 1 and fields[1].strip() else None
        packages.append(PendingPackage(name=name, current_version=None, new_version=new_version))
    return packages


def parse_snap_upgradable_output(raw: str) -> int:
    """Count pending snap refreshes — see `parse_snap_upgradable_packages`."""
    return len(parse_snap_upgradable_packages(raw))


@dataclass
class UpdateCheckResult:
    exit_status: int
    upgradable_count: int
    security_upgradable_count: int
    flatpak_upgradable_count: int
    snap_upgradable_count: int
    output: str
    apt_upgradable_packages: list[PendingPackage] = field(default_factory=list)
    flatpak_upgradable_packages: list[PendingPackage] = field(default_factory=list)
    snap_upgradable_packages: list[PendingPackage] = field(default_factory=list)
    # `apt-mark showhold` — None when the section was missing entirely.
    held_packages: list[str] | None = None


def carry_over_advisories(
    packages: list[PendingPackage], previous: list[dict[str, object]] | None
) -> list[PendingPackage]:
    """Copy `cves`/`urgency` from the previous check's list onto every
    security package whose (name, new version) was already looked up, and
    return the security packages that still need a lookup."""
    known = {
        (str(p.get("name")), str(p.get("new_version"))): p
        for p in previous or []
        if isinstance(p, dict) and p.get("cves") is not None
    }
    missing: list[PendingPackage] = []
    for package in packages:
        if not package.get("security"):
            continue
        before = known.get((package["name"], str(package["new_version"])))
        if before is not None:
            cves = before.get("cves")
            package["cves"] = [str(c) for c in cves] if isinstance(cves, list) else []
            urgency = before.get("urgency")
            package["urgency"] = str(urgency) if urgency else None
        else:
            missing.append(package)
    return missing


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

    Pending apt security updates also get the CVEs they fix, from their
    changelogs (`app.ssh.security_advisories`), over the same connection —
    only for the ones `machine.apt_upgradable_packages` doesn't already
    have an answer for.
    """
    async with machine_connection(machine, secret, connect_timeout_seconds) as conn:
        result = await conn.run(
            with_root_shim(_CHECK_UPDATES_COMMAND), check=False, timeout=run_timeout_seconds
        )
        stdout = result.stdout or ""
        output = stdout if isinstance(stdout, str) else stdout.decode()
        exit_status = result.exit_status if result.exit_status is not None else -1
        apt_packages = parse_apt_upgradable_packages(output)
        missing = carry_over_advisories(apt_packages, machine.apt_upgradable_packages)
        if exit_status == 0 and missing:
            try:
                advisories = await lookup_advisories(
                    conn, [dict(p) for p in missing], run_timeout_seconds
                )
            except (asyncssh.Error, OSError, TimeoutError):
                advisories = {}
            for package in missing:
                advisory = advisories.get(package["name"])
                if advisory is not None:
                    package["cves"] = advisory.cves
                    package["urgency"] = advisory.urgency

    upgradable_count, security_upgradable_count = parse_upgradable_output(output)
    flatpak_packages = parse_flatpak_upgradable_packages(output)
    snap_packages = parse_snap_upgradable_packages(output)
    held_packages = parse_held_packages(output)
    return UpdateCheckResult(
        held_packages=held_packages,
        exit_status=exit_status,
        upgradable_count=upgradable_count,
        security_upgradable_count=security_upgradable_count,
        flatpak_upgradable_count=len(flatpak_packages),
        snap_upgradable_count=len(snap_packages),
        output=output,
        apt_upgradable_packages=apt_packages,
        flatpak_upgradable_packages=flatpak_packages,
        snap_upgradable_packages=snap_packages,
    )


# --- Preview ("what would this update do?") ---
#
# A dry run of the exact same upgrade strategy `build_update_command` would
# run for real, using apt's own simulate mode (`-s`, aka `--simulate` /
# `--just-print` / `--dry-run` / `--recon` / `--no-act` — all synonyms for
# the same flag) for both the upgrade step and `autoremove`, so an operator
# can see what would be *removed* (the risky part of `autoremove`) before
# confirming. Reuses `_apt` (same root-fallback `apt-get -y -q` prefix
# `build_update_command` uses) with `-s` appended — `-y` is harmless
# alongside `-s` (apt never actually prompts in simulate mode either way).
#
# Deliberately apt-only: flatpak/snap have no equivalent "what would be
# removed" concern here (`flatpak update`/`snap refresh` don't remove
# packages the way `autoremove` does), so `check_updates`'s existing
# flatpak/snap counts/lists are all the context the preview page needs for
# those two sources — no new simulation added for them.

_UPGRADE_SIM_MARKER = "===UPGRADE_SIM==="
_AUTOREMOVE_SIM_MARKER = "===AUTOREMOVE_SIM==="
_PREVIEW_SECTION_MARKERS = ("UPGRADE_SIM", "AUTOREMOVE_SIM")

_INST_RE = re.compile(r"^Inst\s+(\S+)\s*(?:\[([^\]]*)\])?\s*\((\S+)")
_REMV_RE = re.compile(r"^Remv\s+(\S+)\s*(?:\[([^\]]*)\])?")


def build_update_preview_command(strategy: UpgradeStrategy) -> str:
    """Build the remote shell script for a dry-run preview of one update
    run — the same `apt-get update` + upgrade-strategy + `autoremove`
    sequence `build_update_command` runs for real, with `-s` (simulate) on
    both apt-mutating steps. `autoclean` and the flatpak/snap steps aren't
    simulated: `autoclean` only deletes already-downloaded `.deb` files
    from the local cache (nothing installed/removed to preview), and
    flatpak/snap have no removal-preview concept relevant here (see the
    section docstring above).
    """
    return (
        "{ "
        f"{_APT_REFRESH_QUIET}; "
        'status=$?; '
        f"echo {_UPGRADE_SIM_MARKER}; "
        f'if [ "$status" -eq 0 ]; then {_upgrade_step(strategy, simulate=True)}; fi; '
        f"echo {_AUTOREMOVE_SIM_MARKER}; "
        f'if [ "$status" -eq 0 ]; then {_apt("-s autoremove")}; fi; '
        'exit "$status"; '
        "} 2>&1"
    )


def parse_apt_simulated_changes(raw: str) -> tuple[list[PendingPackage], list[PendingPackage]]:
    """Parse `apt-get -s`'s simulated-transaction output into (to be
    installed/upgraded, to be removed) — `Inst `-prefixed lines are
    installs/upgrades, `Remv `-prefixed lines are removals. Pure function,
    no I/O, same testing rationale as `parse_apt_upgradable_packages`.

    Typical lines:
        Inst libfoo [1.0-1] (1.1-1 Debian:12.5/stable [amd64])
        Inst libbar (2.0-1 Debian:12.5/stable [amd64])
        Remv libbaz [1.0-1]
    """
    installed_or_upgraded: list[PendingPackage] = []
    removed: list[PendingPackage] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        inst_match = _INST_RE.match(line)
        if inst_match:
            name, current_version, new_version = inst_match.groups()
            installed_or_upgraded.append(
                PendingPackage(
                    name=name, current_version=current_version, new_version=new_version
                )
            )
            continue
        remv_match = _REMV_RE.match(line)
        if remv_match:
            name, current_version = remv_match.groups()
            removed.append(
                PendingPackage(name=name, current_version=current_version, new_version=None)
            )
    return installed_or_upgraded, removed


@dataclass
class UpdatePreviewResult:
    exit_status: int
    output: str
    to_install_or_upgrade: list[PendingPackage] = field(default_factory=list)
    to_remove: list[PendingPackage] = field(default_factory=list)


async def preview_update(
    machine: Machine,
    secret: str | None,
    strategy: UpgradeStrategy,
    connect_timeout_seconds: int,
    run_timeout_seconds: int,
) -> UpdatePreviewResult:
    """Connect (strict pinned host-key verification, as always) and run the
    dry-run preview. Shares `run_system_update`'s long timeout budget, since
    `apt-get update` alone can take a while on a slow mirror even though the
    simulate steps themselves are fast."""
    script = build_update_preview_command(strategy)
    async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
        result = await conn.run(with_root_shim(script), check=False, timeout=run_timeout_seconds)

    stdout = result.stdout or ""
    output = stdout if isinstance(stdout, str) else stdout.decode()
    exit_status = result.exit_status if result.exit_status is not None else -1
    sections = _split_sections(output, _PREVIEW_SECTION_MARKERS)

    upgrade_installed, upgrade_removed = parse_apt_simulated_changes(
        sections.get("UPGRADE_SIM", "")
    )
    _autoremove_installed, autoremove_removed = parse_apt_simulated_changes(
        sections.get("AUTOREMOVE_SIM", "")
    )

    # De-duplicate by name: a package apt already flags for removal during
    # the upgrade step itself (rare, but possible with dist-upgrade) would
    # otherwise also show up from the autoremove step's own simulation.
    to_remove_by_name = {pkg["name"]: pkg for pkg in (*upgrade_removed, *autoremove_removed)}

    return UpdatePreviewResult(
        exit_status=exit_status,
        output=output,
        to_install_or_upgrade=upgrade_installed,
        to_remove=list(to_remove_by_name.values()),
    )


# --- Rollback: snapshot installed dpkg versions, then re-install exactly
# those versions later if an update turns out to be a mistake. Never
# root-required to *read* (dpkg's own database is world-readable); only the
# rollback install itself needs it, same as any other apt write. See
# `app.tasks.jobs._run_machine_update` (captures the snapshot) and
# `_rollback_machine_update` (uses it).
_SNAPSHOT_COMMAND = r"dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null"


def parse_package_snapshot(raw: str) -> dict[str, str]:
    """`{package_name: installed_version}` from `_SNAPSHOT_COMMAND`'s
    tab-separated output. Pure function, no I/O, same reasoning
    `parse_packages_output` is split out for."""
    snapshot: dict[str, str] = {}
    for line in raw.splitlines():
        name, sep, version = line.strip().partition("\t")
        if name and sep and version:
            snapshot[name] = version
    return snapshot


async def capture_package_snapshot(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> dict[str, str]:
    """Connect and list every installed apt package with its exact current
    version — the "before" picture a later rollback diffs against."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(
            with_root_shim(_SNAPSHOT_COMMAND), check=False, timeout=timeout_seconds
        )
    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_package_snapshot(raw)


def build_rollback_command(target_versions: dict[str, str]) -> str:
    """`apt-get install` pinned to `target_versions`' exact
    `package=version` specs, allowing a downgrade. Each `package=version`
    spec is shell-quoted as one token (not that dpkg names/versions
    typically need it — this is defense in depth, not a response to any
    known injection vector: both come straight out of `dpkg-query` against
    the machine's own package database, never from user input). Requires
    those exact old versions to still be resolvable from a configured apt
    source (the local cache, an unchanged mirror, or a snapshot/pinning
    repo) — if the old `.deb` is gone, apt fails with its own clear "unable
    to locate package version" error, surfaced in the run's stored output
    like any other apt failure."""
    specs = " ".join(
        shlex.quote(f"{package}={version}") for package, version in sorted(target_versions.items())
    )
    return f"{{ {_apt(f'{_DPKG_NONINTERACTIVE_FLAGS} --allow-downgrades install {specs}')}; }} 2>&1"


async def run_rollback(
    machine: Machine,
    secret: str | None,
    target_versions: dict[str, str],
    connect_timeout_seconds: int,
    run_timeout_seconds: int,
) -> UpdateResult:
    """Connect and re-install exactly `target_versions`. Buffered (not
    streamed like `run_system_update`) — a rollback installs only the
    packages that actually changed, so it's normally much quicker than a
    full update run, and doesn't warrant the extra complexity of live
    progress."""
    script = build_rollback_command(target_versions)
    async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
        result = await conn.run(with_root_shim(script), check=False, timeout=run_timeout_seconds)
    stdout = result.stdout or ""
    output = stdout if isinstance(stdout, str) else stdout.decode()
    exit_status = result.exit_status if result.exit_status is not None else -1
    return UpdateResult(exit_status=exit_status, output=output)


def parse_held_packages(raw: str) -> list[str] | None:
    """`apt-mark showhold`'s names from the check's `APT_HELD` section,
    sorted; None when the section isn't in the output at all."""
    if _HELD_MARKER not in raw:
        return None
    section = _split_check_sections(raw).get("APT_HELD", "")
    return sorted(
        {line.strip() for line in section.splitlines() if is_safe_package_name(line.strip())}
    )


# --- Holding packages back (`apt-mark hold` / `unhold`) ---


def build_hold_command(package: str, *, hold: bool) -> str:
    """`apt-mark hold|unhold <package>` with the usual sudo-or-root
    fallback. The name is validated (`is_safe_package_name`) before it ever
    gets here, and quoted on top of that."""
    verb = "hold" if hold else "unhold"
    return f"{{ {_with_root_fallback(f'apt-mark {verb} {shlex.quote(package)}')}; }} 2>&1"


async def set_package_hold(
    machine: Machine,
    secret: str | None,
    package: str,
    *,
    hold: bool,
    connect_timeout_seconds: int,
) -> UpdateResult:
    """Hold `package` at its installed version (or release it again).
    Needs root or a sudoers grant for `/usr/bin/apt-mark` — machines
    onboarded by debcontrol 0.78.0+ get one."""
    if not is_safe_package_name(package):
        raise ValueError(f'"{package}" is not a valid package name.')
    async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
        result = await conn.run(
            with_root_shim(build_hold_command(package, hold=hold)),
            check=False,
            timeout=connect_timeout_seconds + 60,
        )
    stdout = result.stdout or ""
    output = stdout if isinstance(stdout, str) else stdout.decode()
    exit_status = result.exit_status if result.exit_status is not None else -1
    return UpdateResult(exit_status=exit_status, output=output)


# --- Changelog of a pending update ---

# More than enough for any release's changes since the installed version.
MAX_CHANGELOG_LINES = 400


def build_changelog_command(package: str) -> str:
    """`apt-get changelog` — fetched by apt from the distribution's own
    changelog server (no root needed), capped."""
    return (
        f"apt-get changelog -- {shlex.quote(package)} 2>/dev/null "
        f"| head -n {MAX_CHANGELOG_LINES * 5}"
    )


_CHANGELOG_HEADER_RE = re.compile(r"^(\S+) \(([^)]+)\)")


def changelog_since(text: str, installed_version: str | None) -> str:
    """The changelog entries newer than `installed_version` — everything
    above that version's own entry — capped at `MAX_CHANGELOG_LINES`. The
    whole (capped) text when that version isn't found."""
    lines = text.splitlines()
    if installed_version:
        for index, line in enumerate(lines):
            match = _CHANGELOG_HEADER_RE.match(line)
            if match and match.group(2) == installed_version and index > 0:
                lines = lines[:index]
                break
    return "\n".join(lines[:MAX_CHANGELOG_LINES]).rstrip()


async def fetch_changelog(
    machine: Machine,
    secret: str | None,
    package: str,
    *,
    installed_version: str | None,
    connect_timeout_seconds: int,
) -> str:
    """The changelog of `package`'s pending update, trimmed to what changed
    since `installed_version`. "" when apt couldn't get one."""
    if not is_safe_package_name(package):
        raise ValueError(f'"{package}" is not a valid package name.')
    async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
        result = await conn.run(
            build_changelog_command(package), check=False, timeout=connect_timeout_seconds + 45
        )
    stdout = result.stdout or ""
    text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
    return changelog_since(text, installed_version)


# --- "This update will need a reboot" ---

# Packages whose new version only takes effect after a reboot.
_REBOOT_PACKAGE_RE = re.compile(
    r"^(linux-image-|linux-modules-|linux-signed|proxmox-kernel-|pve-kernel-|"
    r"intel-microcode$|amd64-microcode$|firmware-|linux-firmware$|systemd$|libc6$|dbus$)"
)
# Proxmox VE's own core — the host keeps working, but its management
# services restart and running guests keep the old QEMU until restarted.
_PVE_CORE_RE = re.compile(
    r"^(pve-manager|proxmox-ve|qemu-server|pve-qemu-kvm|pve-container|pve-cluster|"
    r"pve-ha-manager|proxmox-backup-client|pve-firmware)$"
)


def reboot_hint_packages(
    packages: list[dict[str, object]] | None,
) -> tuple[list[str], list[str]]:
    """(packages that need a reboot to take effect, Proxmox VE core
    packages) among a machine's pending apt updates."""
    reboot: list[str] = []
    pve_core: list[str] = []
    for package in packages or []:
        name = str(package.get("name") or "")
        if _REBOOT_PACKAGE_RE.match(name):
            reboot.append(name)
        if _PVE_CORE_RE.match(name):
            pve_core.append(name)
    return reboot, pve_core
