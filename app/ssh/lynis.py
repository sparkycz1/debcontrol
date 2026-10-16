"""Lynis (https://cisofy.com/lynis/) security audit of a managed machine:
the one shell script that runs `lynis audit system` there, and the parser
for the report it leaves behind.

**Which Lynis.** The one installed on the machine: debcontrol uploads
nothing and runs no code of its own as root. The distributions ship old
releases, so debcontrol prefers CISOfy's own signed apt repository
(`CISOFY_REPO_SETUP`, added by onboarding from 0.115.0, which runs as
root): from there the newest Lynis arrives with ordinary system updates.
A run that asks to install (`install_if_missing`) runs `apt-get install
lynis` first, which installs it or upgrades an older one; connected as
root it also adds that repository when missing. A scoped sudo account may
run apt-get but not write apt's sources, so there it uses whatever
repositories the machine has (CISOfy's, once onboarding added it). A
machine without apt just reports that Lynis is missing.

**Root.** Lynis is run as `sudo -n <lynis>` when the account has a grant
for that exact path (`/usr/sbin/lynis` and `/usr/bin/lynis` are in
`app.ssh.onboarding.SUDO_COMMANDS` from 0.114.0), else as the account
itself: Lynis then skips the tests that need root and says so, and the
audit is stored as not privileged, so its hardening index is not compared
with a full one. Connected as root, the root shim (`app.ssh.shell`) makes
`sudo` a no-op.

**The report.** Written to a file in a fresh `mktemp -d` directory that the
account owns, created empty (mode 600) before Lynis starts: Lynis running
as root truncates and appends to it, which keeps the owner and mode, so
the account can read it back without any further sudo. Only the lines this
module keeps (`_REPORT_KEYS`) leave the machine. The directory is removed
on exit, also when the run fails.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import asyncssh

from app.db.models.machine import Machine
from app.ssh import shell
from app.ssh.client import open_connection
from app.ssh.exceptions import SSHConnectionError

MISSING_MARKER = "DEBCONTROL_LYNIS_MISSING"
INSTALL_FAILED_MARKER = "DEBCONTROL_LYNIS_INSTALL_FAILED"
CISOFY_FAILED_MARKER = "DEBCONTROL_LYNIS_CISOFY_FAILED"
PRIVILEGED_MARKER = "DEBCONTROL_LYNIS_PRIVILEGED"
UNPRIVILEGED_MARKER = "DEBCONTROL_LYNIS_UNPRIVILEGED"
EXIT_MARKER = "DEBCONTROL_LYNIS_EXIT="
REPORT_DELIMITER = "===DEBCONTROL_LYNIS_REPORT==="
OUTPUT_DELIMITER = "===DEBCONTROL_LYNIS_OUTPUT==="

# The fixed install locations, tried before whatever `PATH` finds — a
# non-login SSH session often has no /usr/sbin in its PATH, and the sudo
# grant names exact paths.
_LYNIS_PATHS = ("/usr/sbin/lynis", "/usr/bin/lynis", "/usr/local/bin/lynis")

CISOFY_KEY_URL = "https://packages.cisofy.com/keys/cisofy-software-public.key"
CISOFY_REPO_URL = "https://packages.cisofy.com/community/lynis/deb/"
_CISOFY_LIST = "/etc/apt/sources.list.d/cisofy-lynis.list"

# Adds CISOfy's Lynis repository, as root, on an apt machine that does not
# have it yet: the signing key (armored or binary, named to match, as apt's
# `signed-by` requires) and a source restricted to that key. The new source
# is fetched once on its own; if that fails (no route to packages.cisofy.com,
# a proxy) the key and source are removed again, so a repository the
# machine cannot reach never makes every later `apt-get update` (and so
# every update run) fail. Exits non-zero when the repository is not usable;
# idempotent (a repository already configured is left as it is).
CISOFY_REPO_SETUP = (
    "("
    "command -v apt-get >/dev/null 2>&1 || exit 1; "
    # Already configured, by us, by the Ansible playbook (a .sources file)
    # or by hand: a second entry with another key would break apt.
    "grep -rqs packages.cisofy.com /etc/apt/sources.list /etc/apt/sources.list.d/ && exit 0; "
    "K=/etc/apt/keyrings/cisofy-software-public; "
    "install -d -m 755 /etc/apt/keyrings || exit 1; "
    f'{{ curl -fsSL "{CISOFY_KEY_URL}" -o "$K.tmp" 2>/dev/null '
    f'|| wget -qO "$K.tmp" "{CISOFY_KEY_URL}" 2>/dev/null; }}; '
    '[ -s "$K.tmp" ] || { rm -f "$K.tmp"; exit 1; }; '
    'if grep -q "BEGIN PGP PUBLIC KEY BLOCK" "$K.tmp"; then KF="$K.asc"; else KF="$K.gpg"; fi; '
    'mv "$K.tmp" "$KF" && chmod 644 "$KF" || exit 1; '
    f'echo "deb [signed-by=$KF] {CISOFY_REPO_URL} stable main" > {_CISOFY_LIST}; '
    # `apt-get update` exits 0 also when a source failed to download or
    # verify; only Lynis showing up from that source proves it works.
    "apt-get -q update "
    f"-o Dir::Etc::sourcelist={_CISOFY_LIST} -o Dir::Etc::sourceparts=- "
    "-o APT::Get::List-Cleanup=0 >/dev/null 2>&1; "
    "apt-cache policy lynis 2>/dev/null | grep -q packages.cisofy.com && exit 0; "
    f'rm -f {_CISOFY_LIST} "$KF"; exit 1'
    ")"
)

# The report lines that leave the machine (an extended regex for `grep -E`).
_REPORT_LINES = r"^(lynis_version|hardening_index|lynis_tests_done|warning\[\]|suggestion\[\])="

# A busy machine with many findings is still far below this; it only guards
# the stored row against a pathological report.
MAX_FINDINGS = 400
_MAX_TEXT = 500

_LINE = re.compile(r"^([a-z_]+)(\[\])?=(.*)$")


def build_audit_command(*, install_if_missing: bool) -> str:
    """The whole audit as one script (one SSH exec). Prints the markers
    above and the report's kept lines; see the module docstring."""
    find = (
        "L=; for c in " + " ".join(_LYNIS_PATHS) + ' "$(command -v lynis 2>/dev/null)"; do '
        '[ -n "$c" ] && [ -x "$c" ] && { L="$c"; break; }; done; '
    )
    install = ""
    if install_if_missing:
        install = (
            "export DEBIAN_FRONTEND=noninteractive; "
            # Root: CISOfy's repository, then install or upgrade from it.
            'if [ "$(id -u)" = 0 ] && command -v apt-get >/dev/null 2>&1; then '
            f"{CISOFY_REPO_SETUP} || echo {CISOFY_FAILED_MARKER}; "
            "apt-get -q update >/dev/null 2>&1; "
            "apt-get -y -q install lynis >/dev/null 2>&1 "
            f"|| {{ [ -z \"$L\" ] && echo {INSTALL_FAILED_MARKER}; }}; "
            f"{find}"
            # A scoped sudo account: install or upgrade from the
            # repositories the machine already has (CISOfy's, once
            # onboarding added it).
            "elif command -v apt-get >/dev/null 2>&1; then "
            "sudo -n apt-get -q update >/dev/null 2>&1; "
            "sudo -n apt-get -y -q install lynis >/dev/null 2>&1 "
            f"|| {{ [ -z \"$L\" ] && echo {INSTALL_FAILED_MARKER}; }}; "
            f"{find}"
            "fi; "
        )
    return (
        f"{find}"
        f"{install}"
        f'if [ -z "$L" ]; then echo {MISSING_MARKER}; exit 0; fi; '
        "T=$(mktemp -d /tmp/debcontrol-lynis.XXXXXX) || exit 97; "
        "trap 'rm -rf \"$T\"' EXIT; "
        'R="$T/report.dat"; : > "$R"; chmod 600 "$R"; cd "$T" || exit 97; '
        'if sudo -n -l "$L" >/dev/null 2>&1; then P="sudo -n"; '
        f"echo {PRIVILEGED_MARKER}; else P=; echo {UNPRIVILEGED_MARKER}; fi; "
        '$P "$L" audit system --cronjob --no-log --report-file "$R" >"$T/out" 2>&1; '
        f'rc=$?; echo "{EXIT_MARKER}$rc"; '
        f"echo {REPORT_DELIMITER}; "
        f"grep -E '{_REPORT_LINES}' \"$R\"; "
        f"echo {OUTPUT_DELIMITER}; "
        '[ "$rc" -eq 0 ] || tail -c 1500 "$T/out"'
    )


def _clean(value: str) -> str:
    value = value.strip()
    return "" if value in ("-", "") else value[:_MAX_TEXT]


def _finding(value: str) -> dict[str, str] | None:
    """`TEST-ID|text|detail|solution|` → a finding, `None` for a malformed
    line. Lynis writes `-` for an empty field."""
    parts = value.split("|")
    if len(parts) < 2 or not parts[0].strip():
        return None
    return {
        "test": parts[0].strip()[:32],
        "text": _clean(parts[1]),
        "detail": _clean(parts[2]) if len(parts) > 2 else "",
        "solution": _clean(parts[3]) if len(parts) > 3 else "",
    }


@dataclass
class LynisResult:
    missing: bool = False
    install_failed: bool = False
    # Connected as root and asked to install, but CISOfy's repository could
    # not be added (Lynis may still have come from the distribution).
    cisofy_failed: bool = False
    privileged: bool | None = None
    exit_status: int | None = None
    version: str | None = None
    hardening_index: int | None = None
    tests_done: int | None = None
    warnings: list[dict[str, str]] = field(default_factory=list)
    suggestions: list[dict[str, str]] = field(default_factory=list)
    # The tail of Lynis's own output when it exited non-zero.
    output: str = ""

    @property
    def usable(self) -> bool:
        """A report with a hardening index — what makes an audit a success."""
        return self.hardening_index is not None


def _int(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


# A head marker line → the `LynisResult` field it sets, and to what.
_HEAD_FLAGS: dict[str, tuple[str, bool]] = {
    MISSING_MARKER: ("missing", True),
    INSTALL_FAILED_MARKER: ("install_failed", True),
    CISOFY_FAILED_MARKER: ("cisofy_failed", True),
    PRIVILEGED_MARKER: ("privileged", True),
    UNPRIVILEGED_MARKER: ("privileged", False),
}


def parse_audit_output(text: str) -> LynisResult:
    result = LynisResult()
    section = "head"
    seen: dict[str, set[tuple[str, str, str]]] = {"warning": set(), "suggestion": set()}
    output_lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if line == REPORT_DELIMITER:
            section = "report"
            continue
        if line == OUTPUT_DELIMITER:
            section = "output"
            continue
        if section == "output":
            output_lines.append(line)
            continue
        if section == "head":
            if line in _HEAD_FLAGS:
                attr, value = _HEAD_FLAGS[line]
                setattr(result, attr, value)
            elif line.startswith(EXIT_MARKER):
                result.exit_status = _int(line[len(EXIT_MARKER) :])
            continue
        match = _LINE.match(line)
        if match is None:
            continue
        key, _list, value = match.groups()
        if key == "lynis_version":
            result.version = value.strip()[:32] or None
        elif key == "hardening_index":
            index = _int(value)
            result.hardening_index = index if index is not None and 0 <= index <= 100 else None
        elif key == "lynis_tests_done":
            result.tests_done = _int(value)
        elif key in seen:
            finding = _finding(value)
            if finding is None:
                continue
            # Lynis reports some findings once per check that hit them.
            identity = (finding["test"], finding["text"], finding["detail"])
            if identity in seen[key]:
                continue
            seen[key].add(identity)
            bucket = result.warnings if key == "warning" else result.suggestions
            if len(bucket) < MAX_FINDINGS:
                bucket.append(finding)
    result.output = "\n".join(output_lines).strip()[-1500:]
    return result


async def run_audit(
    machine: Machine,
    secret: str | None,
    *,
    install_if_missing: bool,
    connect_timeout_seconds: int,
    run_timeout_seconds: int,
) -> LynisResult:
    """Run the audit on `machine` and parse what came back. A connection
    or timeout problem raises `SSHConnectionError`. Its own connection
    rather than `app.ssh.exec.run_command`, whose output cap would cut the
    head (the markers) off a report with many findings."""
    command = build_audit_command(install_if_missing=install_if_missing)
    try:
        async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
            result = await shell.run(conn, command, check=False, timeout=run_timeout_seconds)
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(f"Security audit failed on {machine.name}: {exc}") from exc
    return parse_audit_output(shell.output_text(result))
