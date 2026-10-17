#!/usr/bin/env python3
"""Updating debcontrol from its own web UI — the part that runs on the host.

The web container cannot update the stack it runs in (it has no Docker
socket and no access to the checkout, on purpose). Instead, Settings ->
Update drops an empty file into `self-update/request/`, a directory the
`web` container can write; a systemd path unit on the host
(`scripts/install_update_watcher.sh` installs it) notices the file and
runs this script, which does the actual work here, on the host, as the
user who owns the checkout:

    self_update.py handle-requests   # what the path unit runs
    self_update.py check             # what the daily timer runs

- `check`: `git fetch` the checkout's branch and record how far behind
  it is (commits, the version it would update to) in
  `self-update/status/available.json`.
- `upgrade`: run `scripts/upgrade.sh` — the very same script a person
  runs by hand — with its output in `self-update/status/upgrade.log`
  and the outcome in `self-update/status/upgrade.json`.

What the web container writes is only ever a trigger: the *names* of the
files decide what happens (`check`, `upgrade`), their content is never
read, and nothing from it reaches a command line. The status directory
is mounted read-only into the container, so nothing it holds can be
swapped for a symlink to a file this script would then overwrite.

Standard library only (it runs with the host's own python3, outside any
virtualenv), and kept compatible with older python3 releases still
shipped by supported host distributions.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
BASE_DIR = ROOT / "self-update"

# Request names the web container may use; anything else is removed and
# otherwise ignored.
CHECK = "check"
UPGRADE = "upgrade"

# How many pending commits `available.json` lists (subjects only).
MAX_LISTED_COMMITS = 30
GIT_TIMEOUT_SECONDS = 180

_VERSION_RE = re.compile(r'^APP_VERSION = "([^"\n]{1,40})"$', re.MULTILINE)


def _now() -> str:
    # `timezone.utc`, not `datetime.UTC`: that alias needs python 3.11.
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")  # noqa: UP017


def request_dir(base: Path) -> Path:
    return base / "request"


def status_dir(base: Path) -> Path:
    return base / "status"


def write_json(path: Path, data: dict[str, Any]) -> None:
    """Atomically, so the web page never reads half a file."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        Path(tmp).chmod(0o644)
        Path(tmp).replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(tmp).unlink()
        raise


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


@contextlib.contextmanager
def locked(base: Path) -> Iterator[None]:
    """One check or upgrade at a time (the path unit and the timer can
    both fire); the lock file lives outside the directories the container
    sees."""
    with (base / ".lock").open("a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def take_requests(base: Path) -> set[str]:
    """Names of the pending requests — every entry is removed first, so
    the path unit (which fires while the directory is not empty) stops
    firing, whatever the container put there."""
    names: set[str] = set()
    directory = request_dir(base)
    try:
        entries = list(directory.iterdir())
    except OSError:
        return names
    for entry in entries:
        names.add(entry.name)
        try:
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
        except OSError as exc:
            print(f"could not remove {entry}: {exc}", file=sys.stderr)
    return names & {CHECK, UPGRADE}


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed arguments, nothing from a request
        ["git", *args],  # noqa: S607 - the host's own git
        cwd=root,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=True,
    )
    return result.stdout.strip()


def _version_in(text: str) -> str | None:
    match = _VERSION_RE.search(text)
    return match.group(1) if match else None


def local_version(root: Path) -> str | None:
    try:
        return _version_in((root / "app" / "core" / "version.py").read_text(encoding="utf-8"))
    except OSError:
        return None


def check(root: Path, base: Path) -> dict[str, Any]:
    """Fetch and record what an upgrade would bring."""
    path = status_dir(base) / "available.json"
    previous = read_json(path)
    write_json(path, {**previous, "checking": True, "check_started_at": _now()})
    result: dict[str, Any] = {"checking": False, "checked_at": _now()}
    try:
        branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD")
        _git(root, "fetch", "--quiet", "origin", branch)
        remote_ref = f"origin/{branch}"
        log = _git(
            root,
            "log",
            f"--max-count={MAX_LISTED_COMMITS}",
            "--format=%h%x09%s",
            f"HEAD..{remote_ref}",
        )
        result.update(
            ok=True,
            branch=branch,
            local_commit=_git(root, "rev-parse", "HEAD"),
            local_version=local_version(root),
            remote_commit=_git(root, "rev-parse", remote_ref),
            remote_version=_version_in(
                _git(root, "show", f"{remote_ref}:app/core/version.py")
            ),
            behind=int(_git(root, "rev-list", "--count", f"HEAD..{remote_ref}") or 0),
            commits=[
                {"commit": line.split("\t", 1)[0], "subject": line.split("\t", 1)[-1]}
                for line in log.splitlines()
                if line
            ],
            # upgrade.sh refuses to run on a checkout with local changes.
            dirty=bool(_git(root, "status", "--porcelain")),
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        detail = getattr(exc, "stderr", None) or str(exc)
        result.update(ok=False, error=str(detail).strip()[-500:])
    write_json(path, result)
    return result


def _default_upgrade_command(root: Path) -> list[str]:
    return ["bash", str(root / "scripts" / "upgrade.sh")]


def upgrade(
    root: Path,
    base: Path,
    command: Callable[[Path], Sequence[str]] = _default_upgrade_command,
) -> dict[str, Any]:
    """Run `scripts/upgrade.sh`, the same as a person would by hand."""
    status = status_dir(base)
    state_path = status / "upgrade.json"
    log_path = status / "upgrade.log"
    if log_path.exists():
        log_path.replace(status / "upgrade.log.1")

    def commit() -> str | None:
        try:
            return _git(root, "rev-parse", "HEAD")
        except (OSError, subprocess.SubprocessError):
            return None

    state: dict[str, Any] = {
        "state": "running",
        "started_at": _now(),
        "from_commit": commit(),
        "from_version": local_version(root),
    }
    write_json(state_path, state)
    with log_path.open("w", encoding="utf-8") as log:
        log.write(f"==> {state['started_at']} upgrade requested from the web UI\n")
        log.flush()
        try:
            exit_code = subprocess.run(  # noqa: S603 - fixed command, nothing from a request
                list(command(root)),
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            ).returncode
        except OSError as exc:
            log.write(f"error: {exc}\n")
            exit_code = 127
        finished = _now()
        log.write(f"==> {finished} finished with exit code {exit_code}\n")
    state.update(
        state="succeeded" if exit_code == 0 else "failed",
        finished_at=finished,
        exit_code=exit_code,
        to_commit=commit(),
        to_version=local_version(root),
    )
    write_json(state_path, state)
    return state


def mark_interrupted(base: Path) -> None:
    """An upgrade still marked running when the lock is free again was cut
    short (the host rebooted, the service was stopped)."""
    path = status_dir(base) / "upgrade.json"
    state = read_json(path)
    if state.get("state") == "running":
        state.update(state="interrupted", finished_at=_now())
        write_json(path, state)
    available = status_dir(base) / "available.json"
    data = read_json(available)
    if data.get("checking"):
        data["checking"] = False
        write_json(available, data)


def touch_watcher(base: Path) -> None:
    path = status_dir(base) / "watcher.json"
    data = read_json(path)
    if data:
        data["last_run_at"] = _now()
        write_json(path, data)


def handle_requests(
    root: Path,
    base: Path,
    command: Callable[[Path], Sequence[str]] = _default_upgrade_command,
) -> set[str]:
    with locked(base):
        mark_interrupted(base)
        requests = take_requests(base)
        if requests:
            touch_watcher(base)
        if UPGRADE in requests:
            upgrade(root, base, command)
            # Refresh "what is available" so the page shows up to date.
            check(root, base)
        elif CHECK in requests:
            check(root, base)
    return requests


def main(argv: Sequence[str]) -> int:
    if len(argv) != 1 or argv[0] not in {"handle-requests", "check"}:
        print("usage: self_update.py handle-requests|check", file=sys.stderr)
        return 2
    if not status_dir(BASE_DIR).is_dir():
        print(
            f"error: {status_dir(BASE_DIR)} is missing — run "
            "scripts/install_update_watcher.sh first.",
            file=sys.stderr,
        )
        return 1
    if argv[0] == "check":
        with locked(BASE_DIR):
            mark_interrupted(BASE_DIR)
            touch_watcher(BASE_DIR)
            result = check(ROOT, BASE_DIR)
        return 0 if result.get("ok") else 1
    handle_requests(ROOT, BASE_DIR)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
