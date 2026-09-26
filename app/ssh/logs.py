"""Live log viewing for a managed machine — the Logs tab. No persistence:
every view is a fresh, read-only SSH round trip (like the interactive
terminal, just non-interactive and scoped to one command), never stored
anywhere in this app's own DB.

Gated behind `Permission.ACTION_TERMINAL` (see `app.web.routes.machines`'s
`_machine_tabs`/the Logs routes), not the plain `machine.view` every other
read-only tab uses — reading journal/log-file content is a materially
different trust level than "here's the CPU count," even though it needs no
root: journal output routinely includes auth attempts, cron output, and
application errors that can carry secrets. Same tier as the interactive
terminal, which could already read any of this directly — see that
permission's own docstring in `app.db.models.role`.

The "view an arbitrary file" half is restricted to `LOG_FILE_ALLOWED_PATHS`
(`Settings.log_file_allowed_path_list`) — a UX/scope guardrail for an
admin who already has `action.terminal` (who could read the same file
directly in the terminal anyway), not a hard security boundary against
that account itself; see that setting's own docstring in
`app.core.config`.
"""

from __future__ import annotations

import re
import shlex

from app.core.config import get_settings
from app.db.models.machine import Machine
from app.ssh.client import open_connection

DEFAULT_LINE_LIMIT = 200
MAX_LINE_LIMIT = 5000


# Docker's own rule for container names (`[a-zA-Z0-9][a-zA-Z0-9_.-]+`) —
# checked before a name ever reaches the machine, on top of quoting it.
_CONTAINER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$")
DOCKER_NO_ACCESS_MARKER = "@@NOACCESS"
# Sets `$D` to a working docker invocation — plain `docker` for an account
# in the `docker` group, else `sudo -n <docker path>` when a sudoers rule
# allows exactly that binary (onboarding adds one when Docker is present) —
# or prints DOCKER_NO_ACCESS_MARKER and stops. Shared by every Docker
# command this app runs outside the monitoring sample (logs, container
# actions, image update checks).
DOCKER_ACCESS_PROBE = (
    "D=docker; "
    "if ! docker ps -q >/dev/null 2>&1; then "
    'DP="$(command -v docker)"; '
    'if [ -n "$DP" ] && sudo -n -l "$DP" >/dev/null 2>&1; then D="sudo -n $DP"; '
    f"else echo {DOCKER_NO_ACCESS_MARKER}; exit 0; fi; "
    "fi; "
)


class LogAccessError(Exception):
    """A requested file path isn't inside an allowed prefix — never sent to
    the machine at all."""


def is_path_allowed(path: str, allowed_prefixes: list[str]) -> bool:
    """True if `path` is an absolute path under one of `allowed_prefixes`
    (each already normalized with no trailing slash — see
    `Settings.log_file_allowed_path_list`). A `..` segment anywhere in the
    path is rejected outright, before the prefix check even runs — without
    that, a textually-prefixed-but-escaping path like
    "/var/log/../../etc/shadow" would pass a naive `startswith` check."""
    if not path.startswith("/"):
        return False
    if ".." in path.split("/"):
        return False
    return any(path == prefix or path.startswith(f"{prefix}/") for prefix in allowed_prefixes)


def _clamp_lines(lines: int) -> int:
    return max(1, min(lines, MAX_LINE_LIMIT))


# journalctl's own priority names, most to least severe; `-p <name>` shows
# that level and everything more severe.
JOURNAL_PRIORITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")


def normalize_priority(priority: str) -> str:
    """A known `JOURNAL_PRIORITIES` name, or "" (no priority filter)."""
    value = priority.strip().lower()
    return value if value in JOURNAL_PRIORITIES else ""


def build_journal_command(
    *, lines: int, search: str, since: str, until: str, priority: str = ""
) -> str:
    """`journalctl` — no root needed to read the system journal on a
    default Debian/Ubuntu install (the invoking user just needs to be in
    the `systemd-journal`/`adm` group, or the journal to be world-readable,
    both the common case). `-g`/`--since`/`--until` are journalctl's own
    filters, applied server-side rather than piping through `grep`
    ourselves — journalctl's `--since`/`--until` understand a much richer
    set of time expressions ("yesterday", "-1h", ...) than this app would
    otherwise have to parse."""
    parts = ["journalctl", "--no-pager", "-n", str(_clamp_lines(lines))]
    if normalize_priority(priority):
        parts += ["-p", normalize_priority(priority)]
    if search.strip():
        parts += ["-g", shlex.quote(search.strip())]
    if since.strip():
        parts += ["--since", shlex.quote(since.strip())]
    if until.strip():
        parts += ["--until", shlex.quote(until.strip())]
    return " ".join(parts)


def build_list_directory_command(path: str) -> str:
    """`ls -1p` — one name per line, with a trailing `/` on directories (and
    nothing appended to files) — enough for the Logs tab's "browse" picker to
    tell the two apart and build the next link, without an operator needing
    to already know a file's exact path. Restricted to
    `LOG_FILE_ALLOWED_PATHS` the same way `build_file_command` is — see
    `list_directory` below."""
    return f"ls -1p -- {shlex.quote(path)} 2>/dev/null"


def parse_directory_listing(raw: str) -> list[tuple[str, bool]]:
    """`(name, is_dir)` pairs from `build_list_directory_command`'s output,
    hidden (dotfile) entries dropped — a log directory's own hidden files
    are never useful to browse to."""
    entries: list[tuple[str, bool]] = []
    for line in raw.splitlines():
        name = line.strip()
        if not name or name.startswith("."):
            continue
        is_dir = name.endswith("/")
        entries.append((name[:-1] if is_dir else name, is_dir))
    return entries


def build_file_command(*, path: str, lines: int, search: str) -> str:
    """`tail`, or `grep | tail` when searching — the *last* N matches
    within an allowed file, not the first N, so a search against a huge
    log still returns its most recent hits rather than possibly nothing
    from years ago."""
    quoted_path = shlex.quote(path)
    clamped = _clamp_lines(lines)
    if search.strip():
        quoted_search = shlex.quote(search.strip())
        return f"grep -F -- {quoted_search} {quoted_path} 2>/dev/null | tail -n {clamped}"
    return f"tail -n {clamped} -- {quoted_path} 2>/dev/null"


async def view_journal(
    machine: Machine,
    secret: str | None,
    timeout_seconds: int,
    *,
    lines: int = DEFAULT_LINE_LIMIT,
    search: str = "",
    since: str = "",
    until: str = "",
    priority: str = "",
) -> str:
    """Connect to a machine and return the requested slice of its systemd
    journal. Requires a pinned host key."""
    command = build_journal_command(
        lines=lines, search=search, since=since, until=until, priority=priority
    )
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(command, check=False, timeout=timeout_seconds)
    stdout = result.stdout or ""
    return stdout if isinstance(stdout, str) else stdout.decode()


async def view_file(
    machine: Machine,
    secret: str | None,
    timeout_seconds: int,
    *,
    path: str,
    lines: int = DEFAULT_LINE_LIMIT,
    search: str = "",
) -> str:
    """Connect to a machine and return the last N (optionally
    search-matching) lines of one allowed file. Requires a pinned host key.
    Raises `LogAccessError` — never reaching the machine at all — if `path`
    isn't inside `LOG_FILE_ALLOWED_PATHS`."""
    settings = get_settings()
    if not is_path_allowed(path, settings.log_file_allowed_path_list):
        raise LogAccessError(f'"{path}" is outside the allowed log paths.')

    command = build_file_command(path=path, lines=lines, search=search)
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(command, check=False, timeout=timeout_seconds)
    stdout = result.stdout or ""
    return stdout if isinstance(stdout, str) else stdout.decode()


async def list_directory(
    machine: Machine,
    secret: str | None,
    timeout_seconds: int,
    *,
    path: str,
) -> list[tuple[str, bool]]:
    """Connect to a machine and return `(name, is_dir)` for each entry
    directly inside `path` — the Logs tab's "browse" picker, so an operator
    doesn't have to already know a file's exact name/path to view it. Same
    `LOG_FILE_ALLOWED_PATHS` restriction and `LogAccessError` as `view_file`.
    Requires a pinned host key."""
    settings = get_settings()
    if not is_path_allowed(path, settings.log_file_allowed_path_list):
        raise LogAccessError(f'"{path}" is outside the allowed log paths.')

    command = build_list_directory_command(path)
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(command, check=False, timeout=timeout_seconds)
    stdout = result.stdout or ""
    return parse_directory_listing(stdout if isinstance(stdout, str) else stdout.decode())


def is_container_name_valid(name: str) -> bool:
    return bool(_CONTAINER_NAME_RE.match(name))


def build_docker_logs_command(
    *, container: str, lines: int, search: str, since: str, until: str
) -> str:
    """`docker logs --timestamps` for one container, stdout and stderr
    merged (a container's errors usually go to stderr). Same Docker access
    probe as the monitoring sample (`app.ssh.monitoring`): plain `docker`
    for an account in the `docker` group, else `sudo -n docker` when a
    sudoers rule allows exactly that binary, else `DOCKER_NO_ACCESS_MARKER`.
    Searching filters the *whole* log and keeps the last N matches, same as
    `build_file_command`, rather than searching only the last N lines."""
    if not is_container_name_valid(container):
        raise LogAccessError(f'"{container}" is not a valid container name.')
    clamped = _clamp_lines(lines)
    options = ["--timestamps"]
    if since.strip():
        options += ["--since", shlex.quote(since.strip())]
    if until.strip():
        options += ["--until", shlex.quote(until.strip())]
    if not search.strip():
        options += ["--tail", str(clamped)]
    logs = f"$D logs {' '.join(options)} {shlex.quote(container)} 2>&1"
    if search.strip():
        logs += f" | grep -F -- {shlex.quote(search.strip())} | tail -n {clamped}"
    return f"{DOCKER_ACCESS_PROBE}{logs}"


async def view_docker_logs(
    machine: Machine,
    secret: str | None,
    timeout_seconds: int,
    *,
    container: str,
    lines: int = DEFAULT_LINE_LIMIT,
    search: str = "",
    since: str = "",
    until: str = "",
) -> str:
    """Connect to a machine and return one container's recent log lines.
    Requires a pinned host key. Raises `LogAccessError` for an invalid
    container name (never sent to the machine) or when this account can't
    reach the Docker daemon."""
    command = build_docker_logs_command(
        container=container, lines=lines, search=search, since=since, until=until
    )
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(command, check=False, timeout=timeout_seconds)
    stdout = result.stdout or ""
    output = stdout if isinstance(stdout, str) else stdout.decode()
    if output.strip() == DOCKER_NO_ACCESS_MARKER:
        raise LogAccessError(
            "This account can't reach the Docker daemon (add it to the docker group, "
            "or allow `sudo -n docker`)."
        )
    return output


# How much history a live-follow session starts with before streaming.
FOLLOW_INITIAL_LINES = 50


def build_follow_command(
    *, source: str, path: str, container: str, search: str, priority: str = ""
) -> str:
    """The streaming (`-f`) variant of each Logs source, for the live-follow
    WebSocket (`app/web/routes/logs_ws.py`): `journalctl -f`, `tail -F`
    on an allowed file (follows rotation), or `docker logs -f`. A search
    term filters with `grep --line-buffered` so matches stream immediately
    rather than waiting for a pipe buffer to fill. Same validation as the
    one-shot commands: the path allowlist, Docker's container-name rule."""
    term = search.strip()
    grep = f" | grep --line-buffered -F -- {shlex.quote(term)}" if term else ""
    n = FOLLOW_INITIAL_LINES
    if source == "journal":
        options = f" -g {shlex.quote(term)}" if term else ""
        if normalize_priority(priority):
            options += f" -p {normalize_priority(priority)}"
        return f"journalctl --no-pager -f -n {n}{options}"
    if source == "file":
        if not is_path_allowed(path, get_settings().log_file_allowed_path_list):
            raise LogAccessError(f'"{path}" is outside the allowed log paths.')
        return f"tail -n {n} -F -- {shlex.quote(path)} 2>&1{grep}"
    if source == "docker":
        if not is_container_name_valid(container):
            raise LogAccessError(f'"{container}" is not a valid container name.')
        return (
            f"{DOCKER_ACCESS_PROBE}"
            f"$D logs -f --tail {n} --timestamps {shlex.quote(container)} 2>&1{grep}"
        )
    raise LogAccessError(f'Unknown log source "{source}".')
