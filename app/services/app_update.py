"""Updating debcontrol itself from Settings -> Update (and the REST API).

The app cannot update the stack it runs in — the container has no Docker
socket and no access to the git checkout, on purpose. A systemd watcher
on the host does it instead (`scripts/install_update_watcher.sh`,
`scripts/self_update.py`); this module is the app's side of that
conversation, through two directories docker-compose.yml mounts in:

- `request/` (writable): asking for a check or an upgrade is creating an
  empty file named `check` or `upgrade` here. The watcher only looks at
  the name, never the content.
- `status/` (read-only): what the watcher reports back — whether it is
  installed at all (`watcher.json`), the last check (`available.json`),
  the last upgrade (`upgrade.json`) and its output (`upgrade.log`).

Everything read here comes from the host and is still parsed defensively:
a missing, half-written or unexpected file means "nothing known", never
an error page.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.core.version import APP_VERSION

BASE_DIR = Path(os.environ.get("DEBCONTROL_SELF_UPDATE_DIR", "/app/self-update"))

CHECK = "check"
UPGRADE = "upgrade"
REQUEST_KINDS = (CHECK, UPGRADE)

# A request the watcher hasn't picked up within this long means it isn't
# running (the path unit fires within a second or two).
STALE_REQUEST_AFTER = timedelta(minutes=2)
# How much of the upgrade log the page shows (its end).
LOG_TAIL_BYTES = 64 * 1024
_MAX_JSON_BYTES = 256 * 1024
_MAX_COMMITS = 30

# Colour/cursor codes a tool might print even without a terminal.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

UPGRADE_STATES = ("running", "succeeded", "failed", "interrupted")


class WatcherNotInstalledError(Exception):
    """The host watcher isn't installed (or the request directory isn't
    writable), so a request would never be picked up."""


class UpgradeInProgressError(Exception):
    """An upgrade is already requested or running."""


@dataclass(frozen=True)
class PendingCommit:
    commit: str
    subject: str


@dataclass(frozen=True)
class Available:
    checked_at: datetime | None
    checking: bool
    ok: bool
    error: str | None
    branch: str | None
    local_version: str | None
    remote_version: str | None
    remote_commit: str | None
    behind: int
    dirty: bool
    commits: tuple[PendingCommit, ...]

    @property
    def update_available(self) -> bool:
        return self.ok and self.behind > 0


@dataclass(frozen=True)
class UpgradeRun:
    state: str
    started_at: datetime | None
    finished_at: datetime | None
    exit_code: int | None
    from_version: str | None
    to_version: str | None
    from_commit: str | None
    to_commit: str | None


@dataclass(frozen=True)
class AppUpdateStatus:
    installed: bool
    watcher_user: str | None
    installed_at: datetime | None
    pending: tuple[str, ...]
    # The oldest pending request is older than STALE_REQUEST_AFTER.
    pending_stale: bool
    available: Available | None
    upgrade: UpgradeRun | None
    log_tail: str
    current_version: str = APP_VERSION

    @property
    def busy(self) -> bool:
        """Something is happening the page should keep polling for."""
        return bool(
            self.pending
            or (self.available is not None and self.available.checking)
            or (self.upgrade is not None and self.upgrade.state == "running")
        )

    @property
    def update_available(self) -> bool:
        return self.available is not None and self.available.update_available

    def as_dict(self) -> dict[str, object]:
        """The REST API's shape."""

        def iso(value: datetime | None) -> str | None:
            return value.isoformat() if value else None

        available = self.available
        upgrade = self.upgrade
        return {
            "installed": self.installed,
            "current_version": self.current_version,
            "pending": list(self.pending),
            "pending_stale": self.pending_stale,
            "busy": self.busy,
            "update_available": self.update_available,
            "available": None
            if available is None
            else {
                "checked_at": iso(available.checked_at),
                "checking": available.checking,
                "ok": available.ok,
                "error": available.error,
                "branch": available.branch,
                "remote_version": available.remote_version,
                "remote_commit": available.remote_commit,
                "behind": available.behind,
                "dirty": available.dirty,
                "commits": [
                    {"commit": c.commit, "subject": c.subject} for c in available.commits
                ],
            },
            "last_upgrade": None
            if upgrade is None
            else {
                "state": upgrade.state,
                "started_at": iso(upgrade.started_at),
                "finished_at": iso(upgrade.finished_at),
                "exit_code": upgrade.exit_code,
                "from_version": upgrade.from_version,
                "to_version": upgrade.to_version,
                "from_commit": upgrade.from_commit,
                "to_commit": upgrade.to_commit,
            },
        }


def _request_dir(base: Path) -> Path:
    return base / "request"


def _status_dir(base: Path) -> Path:
    return base / "status"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_JSON_BYTES + 1)
    except OSError:
        return {}
    if len(raw) > _MAX_JSON_BYTES:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _str(data: dict[str, Any], key: str, limit: int = 200) -> str | None:
    value = data.get(key)
    return value[:limit] if isinstance(value, str) and value else None


def _int(data: dict[str, Any], key: str) -> int | None:
    value = data.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _time(data: dict[str, Any], key: str) -> datetime | None:
    value = data.get(key)
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _available(data: dict[str, Any]) -> Available | None:
    if not data:
        return None
    raw_commits = data.get("commits")
    commits = tuple(
        PendingCommit(
            commit=str(item.get("commit", ""))[:40], subject=str(item.get("subject", ""))[:300]
        )
        for item in (raw_commits if isinstance(raw_commits, list) else [])[:_MAX_COMMITS]
        if isinstance(item, dict)
    )
    return Available(
        checked_at=_time(data, "checked_at"),
        checking=data.get("checking") is True,
        ok=data.get("ok") is True,
        error=_str(data, "error", 500),
        branch=_str(data, "branch"),
        local_version=_str(data, "local_version", 40),
        remote_version=_str(data, "remote_version", 40),
        remote_commit=_str(data, "remote_commit", 40),
        behind=max(_int(data, "behind") or 0, 0),
        dirty=data.get("dirty") is True,
        commits=commits,
    )


def _upgrade(data: dict[str, Any]) -> UpgradeRun | None:
    state = data.get("state")
    if state not in UPGRADE_STATES:
        return None
    return UpgradeRun(
        state=str(state),
        started_at=_time(data, "started_at"),
        finished_at=_time(data, "finished_at"),
        exit_code=_int(data, "exit_code"),
        from_version=_str(data, "from_version", 40),
        to_version=_str(data, "to_version", 40),
        from_commit=_str(data, "from_commit", 40),
        to_commit=_str(data, "to_commit", 40),
    )


def _log_tail(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(size - LOG_TAIL_BYTES, 0))
            raw = handle.read(LOG_TAIL_BYTES)
    except OSError:
        return ""
    text = raw.decode("utf-8", errors="replace")
    if len(raw) == LOG_TAIL_BYTES and size > LOG_TAIL_BYTES:
        # Drop the partial first line.
        text = text.partition("\n")[2]
    # Progress output rewrites its line with a carriage return; keep the
    # last version of each line.
    lines = [line.rsplit("\r", 1)[-1] for line in _ANSI_RE.sub("", text).split("\n")]
    return "\n".join(lines)


def read_status(base: Path | None = None, *, now: datetime | None = None) -> AppUpdateStatus:
    base = base or BASE_DIR
    now = now or datetime.now(UTC)
    status = _status_dir(base)
    watcher = _read_json(status / "watcher.json")

    pending: list[str] = []
    oldest: datetime | None = None
    for kind in REQUEST_KINDS:
        path = _request_dir(base) / kind
        try:
            mtime = datetime.fromtimestamp(path.lstat().st_mtime, UTC)
        except OSError:
            continue
        pending.append(kind)
        oldest = mtime if oldest is None else min(oldest, mtime)

    return AppUpdateStatus(
        installed=bool(watcher),
        watcher_user=_str(watcher, "user", 64),
        installed_at=_time(watcher, "installed_at"),
        pending=tuple(pending),
        pending_stale=oldest is not None and now - oldest > STALE_REQUEST_AFTER,
        available=_available(_read_json(status / "available.json")),
        upgrade=_upgrade(_read_json(status / "upgrade.json")),
        log_tail=_log_tail(status / "upgrade.log"),
    )


def request(kind: str, base: Path | None = None) -> None:
    """Ask the host watcher for a `check` or an `upgrade`. Raises
    `WatcherNotInstalledError` when nobody would pick it up, and
    `UpgradeInProgressError` for a second upgrade while one is under way."""
    if kind not in REQUEST_KINDS:
        raise ValueError(f"unknown request {kind!r}")
    base = base or BASE_DIR
    current = read_status(base)
    if not current.installed:
        raise WatcherNotInstalledError
    if kind == UPGRADE and (
        UPGRADE in current.pending
        or (current.upgrade is not None and current.upgrade.state == "running")
    ):
        raise UpgradeInProgressError
    path = _request_dir(base) / kind
    try:
        # O_NOFOLLOW: never write through something already sitting there.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise WatcherNotInstalledError from exc
    os.close(fd)
