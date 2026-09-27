"""Which CVEs a pending security update fixes — read from the package's
own Debian changelog on the managed machine.

Every Debian/Ubuntu security upload names the CVEs it fixes in its
changelog entry (`* CVE-2024-1234: ...`), and every entry header carries
an urgency (`openssl (3.0.14-1~deb12u2) bookworm-security; urgency=high`).
`apt-get changelog <package>` prints the changelog of the version apt
would install, newest entry first, so everything above the entry for the
installed version is what the update brings. No CVE database, no API key,
nothing sent anywhere from the debcontrol server: the machine fetches the
changelog from its distribution's changelog server the same way it
fetches packages (`metadata.ftp-master.debian.org` /
`changelogs.ubuntu.com`), and only the parsed CVE ids and urgency are
stored.

Kept cheap on purpose, since it runs inside every update check:

- only for packages from a `*-security` suite, and only for a
  (package, new version) not already looked up — `known` carries the
  previous check's answers forward, so a pending update is fetched once;
- one changelog per *source* package (`libssl3` and `openssl` share one),
  mapped with `dpkg-query`'s `${source:Package}`;
- at most `MAX_LOOKUPS_PER_CHECK` changelogs per check, each capped by
  `timeout`, and the loop stops at the first empty answer — a machine
  with no route to the changelog server costs one timeout, not twenty.

A package whose lookup didn't happen or failed keeps `cves` unset
(`None`, "unknown") and is simply tried again on a later check.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

import asyncssh

from app.ssh.shell import with_root_shim

MAX_LOOKUPS_PER_CHECK = 15
LOOKUP_TIMEOUT_SECONDS = 20
# Changelog lines read per package — the newest entries come first, and
# the ones between the installed and the new version are rarely many.
MAX_CHANGELOG_LINES = 600
# More CVE ids than this for one package are cut (and the count kept).
MAX_CVES_PER_PACKAGE = 50

_PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(:[a-z0-9-]+)?$")
_HEADER_RE = re.compile(r"^(\S+) \(([^)]+)\) [^;]*;\s*urgency=(\w+)", re.IGNORECASE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
_URGENCY_ORDER = ("low", "medium", "high", "critical", "emergency")
_BLOCK_MARKER = "===DEBCONTROL_CHANGELOG==="
_FAILED_MARKER = "===DEBCONTROL_CHANGELOG_FAILED==="


def cve_sort_key(cve: str) -> tuple[int, int]:
    """Newest first when used with `reverse=True` — numeric, so
    CVE-2024-10001 sorts after CVE-2024-9143."""
    parts = cve.split("-")
    try:
        return int(parts[1]), int(parts[2])
    except (IndexError, ValueError):
        return 0, 0


@dataclass(frozen=True)
class Advisory:
    cves: list[str]
    # The highest urgency among the new entries ("low" ... "emergency"),
    # None when no entry header was recognized.
    urgency: str | None


def is_safe_package_name(name: str) -> bool:
    return bool(_PACKAGE_NAME_RE.match(name))


def build_source_map_command(names: list[str]) -> str:
    quoted = " ".join(shlex.quote(n) for n in names if is_safe_package_name(n))
    return (
        "dpkg-query -W -f='${Package}\\t${source:Package}\\n' "
        f"{quoted} 2>/dev/null || true"
    )


def parse_source_map(raw: str) -> dict[str, str]:
    """`binary\\tsource` lines -> {binary: source}. An empty source (dpkg too
    old for `${source:Package}`) maps a binary to itself."""
    mapping: dict[str, str] = {}
    for line in raw.splitlines():
        binary, _, source = line.strip().partition("\t")
        if binary:
            mapping[binary.split(":", 1)[0]] = (source.strip() or binary).split(":", 1)[0]
    return mapping


def build_changelog_command(names: list[str]) -> str:
    """One `apt-get changelog` per package in `names`, each output preceded
    by a marker line; stops at the first empty answer (see the module
    docstring)."""
    parts = []
    for name in names:
        if not is_safe_package_name(name):
            continue
        quoted = shlex.quote(name)
        parts.append(
            f"out=$(timeout {LOOKUP_TIMEOUT_SECONDS} apt-get changelog -q {quoted} 2>/dev/null "
            f"| head -n {MAX_CHANGELOG_LINES}); "
            f'if [ -z "$out" ]; then echo {_FAILED_MARKER}; exit 0; fi; '
            f'echo "{_BLOCK_MARKER} {name}"; printf "%s\\n" "$out"; '
        )
    return "".join(parts) + "exit 0"


def parse_changelog(text: str, installed_version: str | None) -> Advisory:
    """CVE ids and highest urgency of every entry newer than
    `installed_version` (everything, when it's unknown or never reached)."""
    # A binNMU (`1.2-3+b1`) rebuilds a binary without a changelog entry of
    # its own — its source entry is `1.2-3`.
    installed = re.sub(r"\+b\d+$", "", installed_version.strip()) if installed_version else None
    cves: list[str] = []
    seen: set[str] = set()
    urgency_rank = -1
    in_new_entries = False
    for line in text.splitlines():
        header = _HEADER_RE.match(line)
        if header:
            version = header.group(2).strip()
            if installed and version == installed:
                break
            in_new_entries = True
            level = header.group(3).lower()
            if level in _URGENCY_ORDER:
                urgency_rank = max(urgency_rank, _URGENCY_ORDER.index(level))
            continue
        if not in_new_entries:
            continue
        for cve in _CVE_RE.findall(line):
            if cve not in seen:
                seen.add(cve)
                cves.append(cve)
    return Advisory(
        cves=sorted(cves, key=cve_sort_key, reverse=True)[:MAX_CVES_PER_PACKAGE],
        urgency=_URGENCY_ORDER[urgency_rank] if urgency_rank >= 0 else None,
    )


def split_changelog_output(raw: str) -> dict[str, str]:
    """`build_changelog_command`'s output -> {package: changelog text}."""
    blocks: dict[str, str] = {}
    current: str | None = None
    lines: list[str] = []
    for line in raw.splitlines():
        if line.startswith(_BLOCK_MARKER):
            if current is not None:
                blocks[current] = "\n".join(lines)
            current = line[len(_BLOCK_MARKER):].strip()
            lines = []
        elif line.startswith(_FAILED_MARKER):
            break
        elif current is not None:
            lines.append(line)
    if current is not None:
        blocks[current] = "\n".join(lines)
    return blocks


async def lookup_advisories(
    conn: asyncssh.SSHClientConnection,
    packages: list[dict[str, object]],
    run_timeout_seconds: int,
) -> dict[str, Advisory]:
    """{binary package name: Advisory} for the `packages` (security ones,
    not yet looked up) that could be resolved this time. Every package of
    a looked-up source gets that source's advisory."""
    names = [str(p["name"]) for p in packages if is_safe_package_name(str(p["name"]))]
    if not names:
        return {}
    source_result = await conn.run(
        with_root_shim(build_source_map_command(names)), check=False, timeout=run_timeout_seconds
    )
    source_raw = source_result.stdout or ""
    source_map = parse_source_map(
        source_raw if isinstance(source_raw, str) else source_raw.decode()
    )

    by_source: dict[str, list[dict[str, object]]] = {}
    for package in packages:
        name = str(package["name"])
        if name in names:
            by_source.setdefault(source_map.get(name, name), []).append(package)
    # One representative binary per source, fetched in a stable order.
    representatives = {
        source: str(members[0]["name"]) for source, members in sorted(by_source.items())
    }
    wanted = list(representatives.values())[:MAX_LOOKUPS_PER_CHECK]
    if not wanted:
        return {}
    changelog_result = await conn.run(
        with_root_shim(build_changelog_command(wanted)),
        check=False,
        timeout=min(run_timeout_seconds, LOOKUP_TIMEOUT_SECONDS * len(wanted) + 30),
    )
    changelog_raw = changelog_result.stdout or ""
    blocks = split_changelog_output(
        changelog_raw if isinstance(changelog_raw, str) else changelog_raw.decode()
    )

    advisories: dict[str, Advisory] = {}
    for source, representative in representatives.items():
        text = blocks.get(representative)
        if text is None:
            continue
        for package in by_source[source]:
            installed = package.get("current_version")
            advisories[str(package["name"])] = parse_changelog(
                text, str(installed) if installed else None
            )
    return advisories
