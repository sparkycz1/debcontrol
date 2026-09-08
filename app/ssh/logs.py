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

import shlex

from app.core.config import get_settings
from app.db.models.machine import Machine
from app.ssh.client import open_connection

DEFAULT_LINE_LIMIT = 200
MAX_LINE_LIMIT = 5000


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


def build_journal_command(*, lines: int, search: str, since: str, until: str) -> str:
    """`journalctl` — no root needed to read the system journal on a
    default Debian/Ubuntu install (the invoking user just needs to be in
    the `systemd-journal`/`adm` group, or the journal to be world-readable,
    both the common case). `-g`/`--since`/`--until` are journalctl's own
    filters, applied server-side rather than piping through `grep`
    ourselves — journalctl's `--since`/`--until` understand a much richer
    set of time expressions ("yesterday", "-1h", ...) than this app would
    otherwise have to parse."""
    parts = ["journalctl", "--no-pager", "-n", str(_clamp_lines(lines))]
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
) -> str:
    """Connect to a machine and return the requested slice of its systemd
    journal. Requires a pinned host key."""
    command = build_journal_command(lines=lines, search=search, since=since, until=until)
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
