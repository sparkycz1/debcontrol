"""Lynis (https://cisofy.com/lynis/) security audit of a managed machine:
the one shell script that runs `lynis audit system` there, and the parser
for the report it leaves behind.

**Which Lynis.** The one installed on the machine: debcontrol uploads
nothing and runs no code of its own as root. The distributions ship old
releases, so debcontrol prefers CISOfy's own signed apt repository
(`CISOFY_REPO_SETUP`, added by onboarding from 0.115.0, which runs as
root): from there the newest Lynis arrives with ordinary system updates.
Every run (from 0.118.0, no longer an option) runs `apt-get install
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

**debcontrol's own checks** (`app.ssh.security_checks`, based on
vps-audit) run over the same connection first, as their own `sh -s`; Lynis
missing or failing doesn't lose them.

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
from typing import Any

import asyncssh

from app.db.models.machine import Machine
from app.ssh import security_checks, shell
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
LOGFILE_DELIMITER = "===DEBCONTROL_LYNIS_LOGFILE==="

# Lynis's log of the last run, kept on the machine at Lynis's own default
# path: emptied right before every run, so it always holds exactly the
# last one. Owned by the account
# debcontrol connects with (onboarding creates it for the scoped
# `debcontrol` account; connected as root the audit creates it), so that
# account can empty and read it, and Lynis running as root writes into it
# (truncating keeps the owner and mode, as with the report file). When the
# account cannot write it (a scoped account on a machine onboarded before
# 0.139.0, where the file is still root's), the log goes to the run's
# private directory instead and only debcontrol keeps it.
MACHINE_LOGFILE = "/var/log/lynis.log"

# How much of Lynis's own log file (`--logfile`) comes back with a run: its
# end, where a run that failed stopped. Lynis writes a few hundred KB for a
# full audit.
LOGFILE_TAIL_BYTES = 400_000
# The run log kept with an audit (`SecurityAudit.run_log`), at most.
MAX_LOG_CHARS = 1_000_000

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

# The report lines that leave the machine (an extended regex for `grep -E`):
# the findings, the per-setting details behind some of them (`details[]`:
# current and recommended value), and a few facts shown next to them.
_REPORT_LINES = (
    r"^(lynis_version|hardening_index|lynis_tests_done|warning\[\]|suggestion\[\]|details\[\]"
    r"|os_fullname|lynis_update_available|firewall_software\[\]|malware_scanner_installed"
    r"|linux_auditd_running|vulnerable_package\[\])="
)

# A busy machine with many findings is still far below this; it only guards
# the stored row against a pathological report.
MAX_FINDINGS = 400
MAX_DETAILS = 400
MAX_VULNERABLE = 200
_MAX_TEXT = 500

# The checks walk the root file system for SUID programs (capped at five
# minutes on the machine itself); this is the limit on top of that.
CHECKS_TIMEOUT_SECONDS = 6 * 60

_LINE = re.compile(r"^([a-z_]+)(\[\])?=(.*)$")


def build_audit_command() -> str:
    """The whole audit as one script (one SSH exec): install or upgrade
    Lynis, run it, print the markers above and the report's kept lines;
    see the module docstring.

    Everything before `REPORT_DELIMITER` that is not a marker is the run's
    log (`LynisResult.log`): the install step's apt output and Lynis's own
    console output, streamed rather than kept in a file, so a run cut off
    by the time limit still brings back how far it got
    (`run_audit`). After the report comes the tail of Lynis's log file
    (`--logfile`, in the same private directory as the report)."""
    find = (
        "L=; for c in " + " ".join(_LYNIS_PATHS) + ' "$(command -v lynis 2>/dev/null)"; do '
        '[ -n "$c" ] && [ -x "$c" ] && { L="$c"; break; }; done; '
    )
    install = (
        "export DEBIAN_FRONTEND=noninteractive; "
        # Root: CISOfy's repository, then install or upgrade from it.
        'if [ "$(id -u)" = 0 ] && command -v apt-get >/dev/null 2>&1; then '
        'echo "+ CISOfy repository"; '
        f"{CISOFY_REPO_SETUP} || echo {CISOFY_FAILED_MARKER}; "
        'echo "+ apt-get update"; apt-get -q update 2>&1 | tail -n 40; '
        'echo "+ apt-get install lynis"; apt-get -y -q install lynis 2>&1 | tail -n 40; '
        f"{find}"
        f'[ -z "$L" ] && echo {INSTALL_FAILED_MARKER}; '
        # A scoped sudo account: install or upgrade from the
        # repositories the machine already has (CISOfy's, once
        # onboarding added it).
        "elif command -v apt-get >/dev/null 2>&1; then "
        'echo "+ sudo -n apt-get update"; sudo -n apt-get -q update 2>&1 | tail -n 40; '
        'echo "+ sudo -n apt-get install lynis"; '
        "sudo -n apt-get -y -q install lynis 2>&1 | tail -n 40; "
        f"{find}"
        f'[ -z "$L" ] && echo {INSTALL_FAILED_MARKER}; '
        "else echo '+ no apt-get on this machine'; "
        "fi; "
    )
    return (
        f"{find}"
        f"{install}"
        f'if [ -z "$L" ]; then echo {MISSING_MARKER}; exit 0; fi; '
        'echo "+ using $L"; '
        "T=$(mktemp -d /tmp/debcontrol-lynis.XXXXXX) || exit 97; "
        "trap 'rm -rf \"$T\"' EXIT; "
        'R="$T/report.dat"; : > "$R"; chmod 600 "$R"; '
        f'G={MACHINE_LOGFILE}; '
        '[ "$(id -u)" = 0 ] && [ ! -e "$G" ] && install -m 600 /dev/null "$G"; '
        'if [ -f "$G" ] && [ ! -L "$G" ] && { [ "$(id -u)" = 0 ] || [ -O "$G" ]; } '
        '&& : > "$G" 2>/dev/null; then '
        'echo "+ Lynis log on the machine: $G (emptied before this run)"; '
        'else G="$T/lynis.log"; : > "$G"; chmod 600 "$G"; '
        f'echo "+ {MACHINE_LOGFILE} not writable by this account; log kept by debcontrol only"; '
        "fi; "
        'cd "$T" || exit 97; '
        'if sudo -n -l "$L" >/dev/null 2>&1; then P="sudo -n"; '
        f"echo {PRIVILEGED_MARKER}; else P=; echo {UNPRIVILEGED_MARKER}; fi; "
        'echo "+ $P $L audit system --cronjob"; '
        # Lynis's console output goes to stdout as it runs (the log above)
        # and into a file for the failure tail below; `rc` is its own exit
        # status, not the pipe's.
        '{ $P "$L" audit system --cronjob --logfile "$G" --report-file "$R" 2>&1; '
        'echo $? > "$T/rc"; } | tee "$T/out"; '
        'rc=$(cat "$T/rc" 2>/dev/null || echo 98); '
        f'echo "{EXIT_MARKER}$rc"; '
        f"echo {REPORT_DELIMITER}; "
        f"grep -E '{_REPORT_LINES}' \"$R\"; "
        f"echo {OUTPUT_DELIMITER}; "
        '[ "$rc" -eq 0 ] || tail -c 1500 "$T/out"; '
        f"echo {LOGFILE_DELIMITER}; "
        f'tail -c {LOGFILE_TAIL_BYTES} "$G"'
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
    # `details[]`: {"test", "service", "desc", "field", "prefval", "value"}.
    details: list[dict[str, str]] = field(default_factory=list)
    # A few report facts: os, lynis_update_available, firewall_software,
    # malware_scanner, auditd, vulnerable_packages.
    facts: dict[str, Any] = field(default_factory=dict)
    # debcontrol's own checks (`app.ssh.security_checks`), run next to Lynis.
    checks: list[dict[str, str]] = field(default_factory=list)
    # The tail of Lynis's own output when it exited non-zero.
    output: str = ""
    # The run's log: install step and Lynis's console output (`console`),
    # the tail of Lynis's log file (`logfile`); see `build_audit_command`.
    console: str = ""
    logfile: str = ""
    # stderr of the audit script (apt and sudo complaints end up here).
    stderr: str = ""

    @property
    def usable(self) -> bool:
        """A report with a hardening index — what makes an audit a success."""
        return self.hardening_index is not None


# `details[]=KRNL-6000|sysctl|desc:...;field:kernel.kptr_restrict;prefval:2;value:0;|`
_DETAIL_FIELDS = ("desc", "field", "prefval", "value")


def _detail(value: str) -> dict[str, str] | None:
    parts = value.split("|")
    if len(parts) < 3 or not parts[0].strip():
        return None
    detail = {"test": parts[0].strip()[:32], "service": _clean(parts[1])[:64]}
    for item in parts[2].split(";"):
        name, sep, val = item.partition(":")
        if sep and name in _DETAIL_FIELDS:
            detail[name] = _clean(val)[:200]
    if not detail.get("field"):
        return None
    if detail.get("desc") == "No description":
        detail["desc"] = ""
    return detail


# Report key → (fact name, kind): text, flag (0/1) or list.
_FACTS: dict[str, tuple[str, str]] = {
    "os_fullname": ("os", "text"),
    "lynis_update_available": ("lynis_update_available", "flag"),
    "firewall_software": ("firewall_software", "list"),
    "malware_scanner_installed": ("malware_scanner", "flag"),
    "linux_auditd_running": ("auditd", "flag"),
    "vulnerable_package": ("vulnerable_packages", "list"),
}


def _add_fact(facts: dict[str, Any], key: str, value: str) -> None:
    name, kind = _FACTS[key]
    value = _clean(value)[:128]
    if kind == "text":
        if value:
            facts[name] = value
    elif kind == "flag":
        if value in ("0", "1"):
            facts[name] = value == "1"
    else:
        items: list[str] = facts.setdefault(name, [])
        if value and value not in items and len(items) < MAX_VULNERABLE:
            items.append(value)


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


_SECTIONS = {
    REPORT_DELIMITER: "report",
    OUTPUT_DELIMITER: "output",
    LOGFILE_DELIMITER: "logfile",
}


def parse_audit_output(text: str) -> LynisResult:
    result = LynisResult()
    section = "head"
    seen: dict[str, set[tuple[str, str, str]]] = {"warning": set(), "suggestion": set()}
    tail_lines: dict[str, list[str]] = {"output": [], "logfile": []}
    console_lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if line in _SECTIONS:
            section = _SECTIONS[line]
            continue
        if section in tail_lines:
            tail_lines[section].append(line)
            continue
        if section == "head":
            if line in _HEAD_FLAGS:
                attr, flag = _HEAD_FLAGS[line]
                setattr(result, attr, flag)
            elif line.startswith(EXIT_MARKER):
                result.exit_status = _int(line[len(EXIT_MARKER) :])
            console_lines.append(line)
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
        elif key == "details":
            detail = _detail(value)
            if detail is not None and len(result.details) < MAX_DETAILS:
                result.details.append(detail)
        elif key in _FACTS:
            _add_fact(result.facts, key, value)
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
    result.output = "\n".join(tail_lines["output"]).strip()[-1500:]
    result.console = "\n".join(console_lines).strip()[-MAX_LOG_CHARS:]
    result.logfile = "\n".join(tail_lines["logfile"]).strip()[-MAX_LOG_CHARS:]
    return result


class AuditRunError(SSHConnectionError):
    """The audit could not finish: no connection, or it ran out of time.
    `partial_log` is whatever the machine had printed by then (see
    `build_audit_command`), for the run log."""

    def __init__(self, message: str, partial_log: str = "") -> None:
        super().__init__(message)
        self.partial_log = partial_log


def _describe(exc: BaseException, timeout_seconds: int) -> str:
    """A readable reason; `str(TimeoutError())` is empty, which used to
    leave "Security audit failed on web1: " as the whole error."""
    if isinstance(exc, TimeoutError):
        return f"it did not finish within {timeout_seconds} seconds"
    return str(exc) or type(exc).__name__


def _text(value: Any) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else bytes(value).decode(errors="replace")


async def run_audit(
    machine: Machine,
    secret: str | None,
    *,
    connect_timeout_seconds: int,
    run_timeout_seconds: int,
) -> LynisResult:
    """Run the audit on `machine` and parse what came back. A connection
    problem or the time limit raises `AuditRunError` (an
    `SSHConnectionError`) carrying the output so far. Its own connection
    rather than `app.ssh.exec.run_command`, whose output cap would cut the
    head (the markers) off a report with many findings."""
    command = build_audit_command()
    try:
        async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
            checks = await _run_checks(conn)
            result = await shell.run(conn, command, check=False, timeout=run_timeout_seconds)
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        # asyncssh's own TimeoutError keeps what the command printed so far.
        partial = _text(getattr(exc, "stdout", None))
        stderr = _text(getattr(exc, "stderr", None))
        if stderr:
            partial += "\n--- stderr ---\n" + stderr
        raise AuditRunError(
            f"Security audit failed on {machine.name}: "
            f"{_describe(exc, run_timeout_seconds)}",
            partial_log=partial[-MAX_LOG_CHARS:],
        ) from exc
    parsed = parse_audit_output(shell.output_text(result))
    parsed.stderr = _text(result.stderr)[-20_000:]
    parsed.checks = checks
    return parsed


async def _run_checks(conn: asyncssh.SSHClientConnection) -> list[dict[str, str]]:
    """debcontrol's own checks (`app.ssh.security_checks`), fed to `sh -s`
    on stdin. A run that times out only loses the checks, not the audit."""
    try:
        result = await shell.run(
            conn,
            "sh -s",
            input=security_checks.SCRIPT,
            check=False,
            timeout=CHECKS_TIMEOUT_SECONDS,
        )
    except (asyncssh.ProcessError, TimeoutError):
        return []
    return security_checks.parse_output(shell.output_text(result))
