"""Lynis (https://cisofy.com/lynis/) security audit of a managed machine:
the one shell script that runs `lynis audit system` there, and the parser
for the report it leaves behind.

**Which Lynis.** The one installed on the machine (the distribution's
`lynis` package, or CISOfy's own repository): debcontrol uploads nothing
and runs no code of its own as root. When there is none and the run asks
for it, `apt-get install lynis` first (apt-get is already in the
onboarding sudoers grant); a machine without apt just reports that Lynis
is missing.

**Root.** Lynis is run as `sudo -n <lynis>` when the account has a grant
for that exact path (`/usr/sbin/lynis` and `/usr/bin/lynis` are in
`app.ssh.onboarding.SUDO_COMMANDS` from 0.113.0), else as the account
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
PRIVILEGED_MARKER = "DEBCONTROL_LYNIS_PRIVILEGED"
UNPRIVILEGED_MARKER = "DEBCONTROL_LYNIS_UNPRIVILEGED"
EXIT_MARKER = "DEBCONTROL_LYNIS_EXIT="
REPORT_DELIMITER = "===DEBCONTROL_LYNIS_REPORT==="
OUTPUT_DELIMITER = "===DEBCONTROL_LYNIS_OUTPUT==="

# The fixed install locations, tried before whatever `PATH` finds — a
# non-login SSH session often has no /usr/sbin in its PATH, and the sudo
# grant names exact paths.
_LYNIS_PATHS = ("/usr/sbin/lynis", "/usr/bin/lynis", "/usr/local/bin/lynis")

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
            'if [ -z "$L" ] && command -v apt-get >/dev/null 2>&1; then '
            "export DEBIAN_FRONTEND=noninteractive; "
            "(sudo -n apt-get -q update >/dev/null 2>&1 || apt-get -q update >/dev/null 2>&1); "
            "(sudo -n apt-get -y -q install lynis >/dev/null 2>&1 "
            "|| apt-get -y -q install lynis >/dev/null 2>&1) "
            f"|| echo {INSTALL_FAILED_MARKER}; "
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
            if line == MISSING_MARKER:
                result.missing = True
            elif line == INSTALL_FAILED_MARKER:
                result.install_failed = True
            elif line == PRIVILEGED_MARKER:
                result.privileged = True
            elif line == UNPRIVILEGED_MARKER:
                result.privileged = False
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
