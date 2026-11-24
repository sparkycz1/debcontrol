"""Configuration backups of machines: `/etc` (with `/etc/pve`), the
crontabs and the list of installed packages, kept as restic snapshots in
one fleet-wide repository, with retention and the restore of a single
file (Backup & restore -> *Machine configuration*, and each machine's
*Backup* tab).

**Where restic runs.** In debcontrol's own containers (the binary ships in
the image), never on the machine: the machine only runs `tar` and a few
read-only commands over SSH (`app.ssh.config_backup`), so it needs
nothing installed, and the repository's password never leaves
debcontrol. The archive is unpacked into a per-machine staging folder on
the data volume, backed up with restic and removed again.

**Repository.** A local path (by default `<data volume>/config-backups`,
which the full backup of debcontrol does *not* include — copy it off the
host, or use a remote one) or one of restic's remote backends that need
only environment variables (`s3:`, `b2:`, `azure:`, `gs:`, `swift:`,
`rest:`). Each machine is its own restic host (its id), every snapshot is
tagged `debcontrol-config`. The address, password and environment are
stored encrypted; the password and environment are never shown again.
Forgetting the password means losing the backups — restic has no
recovery.

**Retention** runs once a day (`run_maintenance`): `restic forget
--group-by host` with the keep-daily/weekly/monthly rules, `--prune`, and
a `restic check` of the repository's structure.

**Restore.** Browsing a snapshot (`restic ls`) and the changes since the
previous one (`restic diff`) need `machine.view`; anything that returns a
file's content — downloading one file or the whole snapshot, or putting a
file back on the machine — needs `action.terminal`, since `/etc` holds
password hashes and private keys. A file put back on the machine goes to
`~/debcontrol-restore/<snapshot>/<path>` of the SSH account, never over
the original: moving it into place is a deliberate step on the machine.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import asyncssh
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.security import decrypt_secret, encrypt_secret
from app.db.models import config_backup as model
from app.db.models.app_settings import AppSettings
from app.db.models.config_backup import ConfigBackupRun
from app.db.models.machine import Machine
from app.ssh import config_backup as remote
from app.ssh.client import open_connection
from app.ssh.credentials import resolve_machine_credential
from app.ssh.docker_cli import DockerCommandError
from app.ssh.exceptions import SSHConnectionError
from app.ssh.restic import (
    REMOTE_PREFIXES,
    is_repository_valid,
    is_snapshot_valid,
    parse_env_lines,
    redact_repository,
)
from app.ssh.shell import with_root_shim

logger = logging.getLogger(__name__)

RESTIC = "restic"
TAG = "debcontrol-config"
DEFAULT_REPOSITORY_DIR = "config-backups"
STAGING_DIR = "config-backup-staging"
CACHE_DIR = "restic-cache"
RESTORE_DIR = "debcontrol-restore"
# restic waits this long for another restic's lock (backups of several
# machines, the daily prune) instead of failing at once.
RETRY_LOCK = "10m"
# Longest a restic call may take, and one backup as a whole.
RESTIC_TIMEOUT_SECONDS = 30 * 60
QUICK_TIMEOUT_SECONDS = 120
SSH_TIMEOUT_SECONDS = 30 * 60
# A run still "running" after this was lost with its worker.
STALE_AFTER = timedelta(hours=2)
# The largest single file handed out (download, restore to the machine).
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_RUNS_SHOWN = 50
MAX_CHANGES = 2000
# Environment passed on to restic (proxy, CA bundle); nothing else of ours.
_PASS_ENV = (
    "PATH", "HOME", "LANG", "TZ", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR",
)


class ConfigBackupError(Exception):
    """A request that can't be done; `key` is an i18n key for the UI."""

    def __init__(self, key: str, detail: str = "") -> None:
        super().__init__(detail or key)
        self.key = key
        self.detail = detail


# --- The repository --------------------------------------------------------


@dataclass(frozen=True)
class Repository:
    location: str
    password: str
    env: tuple[str, ...] = ()

    @property
    def display(self) -> str:
        return redact_repository(self.location)

    def environ(self) -> dict[str, str]:
        env = {key: os.environ[key] for key in _PASS_ENV if key in os.environ}
        for line in self.env:
            key, _, value = line.partition("=")
            env[key] = value
        env["RESTIC_REPOSITORY"] = self.location
        env["RESTIC_PASSWORD"] = self.password
        env["RESTIC_CACHE_DIR"] = str(data_dir() / CACHE_DIR)
        env["RESTIC_PROGRESS_FPS"] = "0.016"
        return env


def data_dir() -> Path:
    return get_settings().ssh_data_dir.resolve()


def default_location() -> str:
    return str(data_dir() / DEFAULT_REPOSITORY_DIR)


@dataclass(frozen=True)
class SettingsView:
    """What the settings form and the API show — never the secrets."""

    configured: bool
    repository: str
    is_default: bool
    has_env: bool
    keep_daily: int
    keep_weekly: int
    keep_monthly: int
    maintenance_at: datetime | None
    maintenance_error: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "repository": self.repository,
            "default_repository": self.is_default,
            "has_environment": self.has_env,
            "keep_daily": self.keep_daily,
            "keep_weekly": self.keep_weekly,
            "keep_monthly": self.keep_monthly,
            "maintenance_at": self.maintenance_at.isoformat() if self.maintenance_at else None,
            "maintenance_error": self.maintenance_error,
        }


def settings_view(settings: AppSettings) -> SettingsView:
    return SettingsView(
        configured=settings.config_backup_password_encrypted is not None,
        repository=settings.config_backup_repository_display or default_location(),
        is_default=settings.config_backup_repository_encrypted is None,
        has_env=settings.config_backup_env_encrypted is not None,
        keep_daily=settings.config_backup_keep_daily,
        keep_weekly=settings.config_backup_keep_weekly,
        keep_monthly=settings.config_backup_keep_monthly,
        maintenance_at=settings.config_backup_maintenance_at,
        maintenance_error=settings.config_backup_maintenance_error,
    )


def repository_of(settings: AppSettings) -> Repository | None:
    """The configured repository, or None until a password is set."""
    if settings.config_backup_password_encrypted is None:
        return None
    location = (
        decrypt_secret(settings.config_backup_repository_encrypted)
        if settings.config_backup_repository_encrypted is not None
        else default_location()
    )
    env = (
        tuple(parse_env_lines(decrypt_secret(settings.config_backup_env_encrypted)))
        if settings.config_backup_env_encrypted is not None
        else ()
    )
    return Repository(location, decrypt_secret(settings.config_backup_password_encrypted), env)


@dataclass
class SettingsChange:
    """A settings form or API body. `None` = leave as it is; `repository=""`
    = back to the default local repository; `environment=""` = remove it."""

    repository: str | None = None
    password: str | None = None
    environment: str | None = None
    keep_daily: int | None = None
    keep_weekly: int | None = None
    keep_monthly: int | None = None


MAX_KEEP = 1000
# debcontrol's own code (`/app` in the image), where a local repository
# must not go — the data volume below it is fine.
_APP_ROOT = Path(__file__).resolve().parents[2]


def _inside_app(location: str) -> bool:
    if not location.startswith("/"):
        return False
    path = Path(os.path.normpath(location))
    data = data_dir()
    return path.is_relative_to(_APP_ROOT) and not path.is_relative_to(data)


def apply_settings(settings: AppSettings, change: SettingsChange) -> list[str]:
    """Validate and store `change`; returns the names of what changed.
    Raises `ConfigBackupError` (nothing stored) for an invalid value."""
    changed: list[str] = []
    repository = change.repository.strip() if change.repository is not None else None
    if repository and (not is_repository_valid(repository) or _inside_app(repository)):
        raise ConfigBackupError("config_backup.error.repository")
    env_lines: list[str] | None = None
    if change.environment is not None and change.environment.strip():
        try:
            env_lines = parse_env_lines(change.environment)
        except DockerCommandError as exc:
            raise ConfigBackupError("config_backup.error.environment", str(exc)) from exc
    if change.password is not None and change.password and len(change.password) < 8:
        raise ConfigBackupError("config_backup.error.password")
    keeps = {
        "keep_daily": change.keep_daily,
        "keep_weekly": change.keep_weekly,
        "keep_monthly": change.keep_monthly,
    }
    for value in keeps.values():
        if value is not None and not 0 <= value <= MAX_KEEP:
            raise ConfigBackupError("config_backup.error.keep")
    final = {
        name: value if value is not None else getattr(settings, f"config_backup_{name}")
        for name, value in keeps.items()
    }
    if not any(final.values()):
        raise ConfigBackupError("config_backup.error.keep")

    if repository is not None:
        if repository:
            settings.config_backup_repository_encrypted = encrypt_secret(repository)
            settings.config_backup_repository_display = redact_repository(repository)
        else:
            settings.config_backup_repository_encrypted = None
            settings.config_backup_repository_display = None
        changed.append("repository")
    if change.password:
        settings.config_backup_password_encrypted = encrypt_secret(change.password)
        changed.append("password")
    if change.environment is not None:
        settings.config_backup_env_encrypted = (
            encrypt_secret("\n".join(env_lines)) if env_lines else None
        )
        changed.append("environment")
    for name, value in keeps.items():
        if value is not None and value != getattr(settings, f"config_backup_{name}"):
            setattr(settings, f"config_backup_{name}", value)
            changed.append(name)
    return changed


# --- Running restic ----------------------------------------------------------


@dataclass
class ResticResult:
    returncode: int
    stdout: bytes
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def error(self) -> str:
        lines = [line for line in self.stderr.splitlines() if line.strip()]
        return (lines[-1] if lines else f"restic exited with {self.returncode}")[:1000]

    def json_lines(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for raw in self.stdout.decode("utf-8", "replace").splitlines():
            raw = raw.strip()
            if not raw.startswith("{"):
                continue
            with contextlib.suppress(ValueError):
                value = json.loads(raw)
                if isinstance(value, dict):
                    items.append(value)
        return items


async def run_restic(
    repo: Repository,
    *args: str,
    cwd: Path | None = None,
    timeout: float = QUICK_TIMEOUT_SECONDS,  # noqa: ASYNC109 - also kills restic
) -> ResticResult:
    """`restic <args>` against `repo`; arguments go straight to the binary,
    never through a shell."""
    binary = shutil.which(RESTIC)
    if binary is None:
        raise ConfigBackupError("config_backup.error.no_restic")
    (data_dir() / CACHE_DIR).mkdir(parents=True, exist_ok=True)
    process = await asyncio.create_subprocess_exec(
        binary,
        *args,
        cwd=str(cwd) if cwd else None,
        env=repo.environ(),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.wait()
        return ResticResult(124, b"", "restic took too long and was stopped.")
    return ResticResult(process.returncode or 0, stdout, stderr.decode("utf-8", "replace"))


async def stream_restic(repo: Repository, *args: str) -> AsyncIterator[bytes]:
    """`restic <args>`'s standard output in chunks (a whole-snapshot
    archive); stops restic if the reader goes away."""
    binary = shutil.which(RESTIC)
    if binary is None:
        raise ConfigBackupError("config_backup.error.no_restic")
    process = await asyncio.create_subprocess_exec(
        binary,
        *args,
        env=repo.environ(),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert process.stdout is not None
    try:
        while chunk := await process.stdout.read(65536):
            yield chunk
    finally:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        await process.wait()


async def ensure_repository(repo: Repository) -> None:
    """Create the repository when it doesn't exist yet (restic exit code
    10); raises `ConfigBackupError` when it can't be opened."""
    if not repo.location.startswith(REMOTE_PREFIXES):
        Path(repo.location).parent.mkdir(parents=True, exist_ok=True)
    result = await run_restic(repo, "cat", "config", "--retry-lock", RETRY_LOCK)
    if result.ok:
        return
    if result.returncode == 10:
        created = await run_restic(repo, "init")
        if created.ok or "already" in created.stderr:
            return
        raise ConfigBackupError("config_backup.error.repository_open", created.error())
    raise ConfigBackupError("config_backup.error.repository_open", result.error())


async def current_repository(db: AsyncSession) -> Repository:
    repo = repository_of(await get_or_create_app_settings(db))
    if repo is None:
        raise ConfigBackupError("config_backup.error.not_configured")
    return repo


# --- Backing up --------------------------------------------------------------


def eligible(machine: Machine) -> bool:
    return bool(machine.host_key_fingerprint)


async def open_run(db: AsyncSession, machine_id: uuid.UUID) -> ConfigBackupRun | None:
    result = await db.execute(
        select(ConfigBackupRun)
        .where(
            ConfigBackupRun.machine_id == machine_id,
            ConfigBackupRun.status.in_(model.OPEN_STATUSES),
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def queue_backups(
    db: AsyncSession, machines: list[Machine], *, started_by: str
) -> tuple[list[ConfigBackupRun], int]:
    """A run for each machine that can be backed up and has none waiting
    or under way; commits and queues one task per run. Returns the runs
    and how many machines were skipped."""
    from app.tasks import config_backup as tasks

    if repository_of(await get_or_create_app_settings(db)) is None:
        raise ConfigBackupError("config_backup.error.not_configured")
    runs: list[ConfigBackupRun] = []
    skipped = 0
    for machine in machines:
        if not eligible(machine) or await open_run(db, machine.id) is not None:
            skipped += 1
            continue
        run = ConfigBackupRun(machine_id=machine.id, status=model.PENDING, started_by=started_by)
        db.add(run)
        runs.append(run)
    await db.commit()
    for run in runs:
        tasks.run_config_backup.delay(str(run.id))
    return runs, skipped


async def _read_capped(reader: Any, limit: int) -> bytes:
    """Everything `reader` gives until EOF, keeping the first `limit` bytes."""
    kept = bytearray()
    while chunk := await reader.read(65536):
        if len(kept) < limit:
            kept += chunk[: limit - len(kept)]
    return bytes(kept)


@dataclass
class Collected:
    unpacked: remote.Unpacked
    unreadable: list[str]


async def _collect(machine: Machine, secret: str | None, connect_timeout: int, dest: Path,
                   archive: Path) -> Collected:
    """Copy the machine's files and package lists into `dest` (over SSH)."""
    async with await open_connection(machine, secret, connect_timeout) as conn:
        listed = await conn.run(remote.PACKAGES_COMMAND, check=False, timeout=300)
        raw = listed.stdout or ""
        packages = remote.split_sections(
            raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
        )
        written = 0
        async with conn.create_process(
            with_root_shim(remote.TAR_COMMAND), encoding=None
        ) as process:
            stderr_task = asyncio.create_task(_read_capped(process.stderr, 256 * 1024))
            with archive.open("wb") as out:
                while True:
                    chunk = await asyncio.wait_for(process.stdout.read(65536), 600)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > remote.MAX_ARCHIVE_BYTES:
                        process.terminate()
                        raise remote.ArchiveError("The archive is larger than the limit.")
                    out.write(chunk)
            await asyncio.wait_for(process.wait(), 120)
            stderr_raw = await stderr_task
            exit_status = process.exit_status
        stderr = stderr_raw.decode("utf-8", "replace")
    if written == 0:
        last = [line for line in stderr.splitlines() if line.strip()]
        raise remote.ArchiveError(last[-1][:500] if last else f"tar exited with {exit_status}.")
    unpacked = await asyncio.to_thread(remote.unpack, archive, dest)
    unreadable = remote.unreadable_paths(stderr)[: remote.MAX_LISTED_UNREADABLE]
    await asyncio.to_thread(
        remote.write_meta, dest, packages=packages, unpacked=unpacked, unreadable=unreadable
    )
    return Collected(unpacked, unreadable)


def _summary(result: ResticResult) -> dict[str, Any]:
    for item in reversed(result.json_lines()):
        if item.get("message_type") == "summary":
            return dict(item)
    return {}


async def _finish(
    run_id: uuid.UUID,
    status: str,
    *,
    error: str | None = None,
    **values: Any,
) -> ConfigBackupRun | None:
    from app.db import session as db_session
    from app.db.models.notification_rule import NotificationEventType
    from app.services.notifications import notify

    async with db_session.AsyncSessionLocal() as db:
        run = await db.get(ConfigBackupRun, run_id)
        if run is None:
            return None
        now = datetime.now(UTC)
        run.status = status
        run.error = error[:1024] if error else None
        run.finished_at = now
        for key, value in values.items():
            setattr(run, key, value)
        machine = await db.get(Machine, run.machine_id)
        if machine is not None:
            machine.config_backup_at = now
            machine.config_backup_status = status
            if status in model.STORED_STATUSES:
                machine.config_backup_last_success_at = now
        await db.commit()
        if status == model.FAILED and machine is not None:
            await notify(
                db,
                NotificationEventType.CONFIG_BACKUP_FAILED,
                machine=machine,
                context={"details": run.error or ""},
            )
        return run


async def run_backup(run_id: uuid.UUID) -> str:
    """Do one run (the Celery task's body). Returns its final status."""
    from app.db import session as db_session

    async with db_session.AsyncSessionLocal() as db:
        run = await db.get(ConfigBackupRun, run_id)
        if run is None or run.status != model.PENDING:
            return run.status if run is not None else "missing"
        machine = await db.get(Machine, run.machine_id)
        settings = await get_or_create_app_settings(db)
        repo = repository_of(settings)
        if machine is None:
            return model.FAILED
        run.status = model.RUNNING
        run.started_at = datetime.now(UTC)
        await db.commit()
        secret = await resolve_machine_credential(machine, db)
        connect_timeout = settings.ssh_connect_timeout
        db.expunge(machine)

    if repo is None:
        await _finish(run_id, model.FAILED, error="No repository is configured.")
        return model.FAILED
    staging = data_dir() / STAGING_DIR / str(machine.id)
    tree = staging / "root"
    try:
        await asyncio.to_thread(shutil.rmtree, staging, True)
        tree.mkdir(parents=True, mode=0o700)
        staging.chmod(0o700)
        collected = await asyncio.wait_for(
            _collect(machine, secret, connect_timeout, tree, staging / "archive.tar"),
            SSH_TIMEOUT_SECONDS,
        )
        (staging / "archive.tar").unlink(missing_ok=True)
        await ensure_repository(repo)
        result = await run_restic(
            repo,
            "backup", ".",
            "--host", str(machine.id),
            "--tag", TAG,
            "--ignore-inode", "--ignore-ctime",
            "--retry-lock", RETRY_LOCK,
            "--json",
            cwd=tree,
            timeout=RESTIC_TIMEOUT_SECONDS,
        )
        summary = _summary(result)
        if not result.ok and not summary.get("snapshot_id"):
            raise ConfigBackupError("config_backup.error.restic", result.error())
    except (ConfigBackupError, remote.ArchiveError, SSHConnectionError, asyncssh.Error,
            OSError, TimeoutError) as exc:
        detail = exc.detail if isinstance(exc, ConfigBackupError) and exc.detail else str(exc)
        await _finish(run_id, model.FAILED, error=detail or type(exc).__name__)
        return model.FAILED
    finally:
        await asyncio.to_thread(shutil.rmtree, staging, True)

    status = model.PARTIAL if collected.unreadable else model.SUCCEEDED
    await _finish(
        run_id,
        status,
        snapshot_id=str(summary.get("snapshot_id") or "")[:64] or None,
        size_bytes=collected.unpacked.size_bytes,
        file_count=collected.unpacked.file_count,
        unreadable_count=len(collected.unreadable),
        added_bytes=_int(summary.get("data_added")),
    )
    return status


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


# --- Reading back ----------------------------------------------------------


async def list_runs(db: AsyncSession, machine_id: uuid.UUID, limit: int = MAX_RUNS_SHOWN) -> list[
    ConfigBackupRun
]:
    result = await db.execute(
        select(ConfigBackupRun)
        .where(ConfigBackupRun.machine_id == machine_id)
        .order_by(ConfigBackupRun.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


@dataclass(frozen=True)
class Snapshot:
    id: str
    short_id: str
    time: datetime | None
    files: int | None
    size: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "short_id": self.short_id,
            "time": self.time.isoformat() if self.time else None,
            "files": self.files,
            "size_bytes": self.size,
        }


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_snapshots(raw: bytes) -> list[Snapshot]:
    try:
        items = json.loads(raw.decode("utf-8", "replace") or "[]")
    except ValueError:
        return []
    snapshots: list[Snapshot] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or not is_snapshot_valid(str(item.get("id") or "")):
            continue
        raw_summary = item.get("summary")
        summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        snapshots.append(
            Snapshot(
                id=str(item["id"]),
                short_id=str(item.get("short_id") or str(item["id"])[:8]),
                time=_parse_time(item.get("time")),
                files=_int(summary.get("total_files_processed")),
                size=_int(summary.get("total_bytes_processed")),
            )
        )
    snapshots.sort(key=lambda s: s.time or datetime.min.replace(tzinfo=UTC), reverse=True)
    return snapshots


async def snapshots(repo: Repository, machine_id: uuid.UUID) -> list[Snapshot]:
    """The machine's snapshots in the repository, newest first."""
    result = await run_restic(
        repo, "snapshots", "--host", str(machine_id), "--tag", TAG, "--json",
        "--no-lock",
    )
    if not result.ok:
        if result.returncode == 10:
            return []
        raise ConfigBackupError("config_backup.error.repository_open", result.error())
    return parse_snapshots(result.stdout)


async def find_snapshot(repo: Repository, machine_id: uuid.UUID, snapshot_id: str) -> tuple[
    Snapshot, Snapshot | None
]:
    """The snapshot (by full or short id) and the one before it; raises
    `ConfigBackupError` when the machine has no such snapshot — so one
    machine's page can never open another machine's snapshot."""
    if not is_snapshot_valid(snapshot_id) or snapshot_id == "latest":
        raise ConfigBackupError("config_backup.error.snapshot")
    found = await snapshots(repo, machine_id)
    for index, snap in enumerate(found):
        if snap.id == snapshot_id or snap.short_id == snapshot_id:
            return snap, found[index + 1] if index + 1 < len(found) else None
    raise ConfigBackupError("config_backup.error.snapshot")


@dataclass(frozen=True)
class Entry:
    path: str
    type: str
    size: int | None
    mode: str
    mtime: datetime | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "type": self.type,
            "size_bytes": self.size,
            "permissions": self.mode,
            "modified_at": self.mtime.isoformat() if self.mtime else None,
        }


def parse_ls(result: ResticResult) -> list[Entry]:
    entries: list[Entry] = []
    for item in result.json_lines():
        if item.get("message_type") != "node" and item.get("struct_type") != "node":
            continue
        path = str(item.get("path") or "")
        if not path or not remote.is_safe_member_path(path):
            continue
        entries.append(
            Entry(
                path=path,
                type=str(item.get("type") or "file"),
                size=_int(item.get("size")),
                mode=str(item.get("permissions") or ""),
                mtime=_parse_time(item.get("mtime")),
            )
        )
    return entries


async def list_entries(repo: Repository, snapshot: Snapshot) -> list[Entry]:
    result = await run_restic(
        repo, "ls", snapshot.id, "--json", "--no-lock", timeout=RESTIC_TIMEOUT_SECONDS
    )
    if not result.ok:
        raise ConfigBackupError("config_backup.error.restic", result.error())
    return parse_ls(result)


@dataclass
class Changes:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def total(self) -> int:
        return len(self.added) + len(self.removed) + len(self.modified)

    def as_dict(self) -> dict[str, Any]:
        return {
            "added": self.added,
            "removed": self.removed,
            "modified": self.modified,
            "truncated": self.truncated,
        }


def parse_diff(result: ResticResult) -> Changes:
    """`restic diff --json`: "+" added, "-" removed, "M"/"T" content or
    type changed. Metadata-only changes ("U") are left out — every backup
    unpacks the files afresh, so their ctime always differs."""
    changes = Changes()
    for item in result.json_lines():
        if item.get("message_type") != "change":
            continue
        path = str(item.get("path") or "")
        modifier = str(item.get("modifier") or "")
        if not path or path.startswith(f"/{remote.META_DIR}/permissions"):
            continue
        if changes.total >= MAX_CHANGES:
            changes.truncated = True
            break
        if modifier.startswith("+"):
            changes.added.append(path)
        elif modifier.startswith("-"):
            changes.removed.append(path)
        elif "M" in modifier or "T" in modifier:
            changes.modified.append(path)
    return changes


async def changes_since(repo: Repository, previous: Snapshot, snapshot: Snapshot) -> Changes:
    result = await run_restic(
        repo, "diff", previous.id, snapshot.id, "--json", "--no-lock",
        timeout=RESTIC_TIMEOUT_SECONDS,
    )
    if not result.ok:
        raise ConfigBackupError("config_backup.error.restic", result.error())
    return parse_diff(result)


async def read_file(repo: Repository, snapshot: Snapshot, path: str) -> bytes:
    """One regular file of the snapshot (at most `MAX_FILE_BYTES`)."""
    if not remote.is_safe_member_path(path):
        raise ConfigBackupError("config_backup.error.path")
    entry = next((e for e in await list_entries(repo, snapshot) if e.path == path), None)
    if entry is None or entry.type != "file":
        raise ConfigBackupError("config_backup.error.path")
    if (entry.size or 0) > MAX_FILE_BYTES:
        raise ConfigBackupError("config_backup.error.too_large")
    result = await run_restic(repo, "dump", snapshot.id, path, "--no-lock")
    if not result.ok:
        raise ConfigBackupError("config_backup.error.restic", result.error())
    return result.stdout[:MAX_FILE_BYTES]


def archive_stream(repo: Repository, snapshot: Snapshot) -> AsyncIterator[bytes]:
    """The whole snapshot as a tar archive."""
    return stream_restic(repo, "dump", "--archive", "tar", "--no-lock", snapshot.id, "/")


def safe_filename(name: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in name).strip("._")
    return cleaned[:120] or "file"


def archive_name(machine: Machine, snapshot: Snapshot) -> str:
    stamp = snapshot.time.strftime("%Y%m%d-%H%M") if snapshot.time else snapshot.short_id
    return f"{safe_filename(machine.name)}-config-{stamp}.tar"


def restore_target(snapshot: Snapshot, path: str) -> str:
    """Where a restored file goes, relative to the SSH account's home."""
    return f"{RESTORE_DIR}/{snapshot.short_id}{path}"


async def restore_to_machine(
    db: AsyncSession, machine: Machine, repo: Repository, snapshot: Snapshot, path: str
) -> str:
    """Put one file of the snapshot into the SSH account's home on the
    machine; returns the full path it was written to."""
    content = await read_file(repo, snapshot, path)
    settings = await get_or_create_app_settings(db)
    secret = await resolve_machine_credential(machine, db)
    target = restore_target(snapshot, path)
    try:
        async with await open_connection(machine, secret, settings.ssh_connect_timeout) as conn:
            result = await conn.run(
                remote.restore_command(target), input=content, encoding=None, check=False,
                timeout=300,
            )
    except (SSHConnectionError, asyncssh.Error, OSError, TimeoutError) as exc:
        raise ConfigBackupError("config_backup.error.restore", str(exc)) from exc
    if result.exit_status != 0:
        stderr = result.stderr if isinstance(result.stderr, bytes) else b""
        raise ConfigBackupError(
            "config_backup.error.restore", stderr.decode("utf-8", "replace").strip()[:500]
        )
    stdout = result.stdout if isinstance(result.stdout, bytes) else b""
    home = stdout.decode("utf-8", "replace").strip().splitlines()[-1:] or ["~"]
    return f"{home[0].rstrip('/')}/{target}"


# --- The fleet ---------------------------------------------------------------


@dataclass(frozen=True)
class FleetRow:
    machine: Machine
    last_run: ConfigBackupRun | None
    running: bool


async def fleet_rows(db: AsyncSession, machines: list[Machine]) -> list[FleetRow]:
    """Each machine with its newest run, for the fleet page."""
    ids = [m.id for m in machines]
    latest: dict[uuid.UUID, ConfigBackupRun] = {}
    if ids:
        newest = (
            select(
                ConfigBackupRun.machine_id,
                func.max(ConfigBackupRun.created_at).label("created_at"),
            )
            .where(ConfigBackupRun.machine_id.in_(ids))
            .group_by(ConfigBackupRun.machine_id)
            .subquery()
        )
        result = await db.execute(
            select(ConfigBackupRun).join(
                newest,
                (ConfigBackupRun.machine_id == newest.c.machine_id)
                & (ConfigBackupRun.created_at == newest.c.created_at),
            )
        )
        for run in result.scalars().all():
            latest[run.machine_id] = run
    return [
        FleetRow(
            machine=m,
            last_run=latest.get(m.id),
            running=latest.get(m.id) is not None
            and latest[m.id].status in model.OPEN_STATUSES,
        )
        for m in machines
    ]


# --- Maintenance -------------------------------------------------------------


def keep_args(settings: AppSettings) -> list[str]:
    args: list[str] = []
    for name, flag in (
        ("keep_daily", "--keep-daily"),
        ("keep_weekly", "--keep-weekly"),
        ("keep_monthly", "--keep-monthly"),
    ):
        value = getattr(settings, f"config_backup_{name}")
        if value:
            args += [flag, str(value)]
    return args


async def fail_stale_runs(db: AsyncSession, now: datetime | None = None) -> int:
    """Runs left "running"/"pending" by a worker that went away."""
    now = now or datetime.now(UTC)
    result = await db.execute(
        update(ConfigBackupRun)
        .where(
            ConfigBackupRun.status.in_(model.OPEN_STATUSES),
            ConfigBackupRun.created_at < now - STALE_AFTER,
        )
        .values(status=model.FAILED, finished_at=now, error="The backup did not finish.")
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return int(getattr(result, "rowcount", 0) or 0)


async def run_maintenance(db: AsyncSession) -> str | None:
    """Retention (`forget --prune`) and a structure check; returns the
    error, or None. Stores the outcome in the settings."""
    await fail_stale_runs(db)
    settings = await get_or_create_app_settings(db)
    repo = repository_of(settings)
    if repo is None:
        return None
    error: str | None = None
    try:
        snaps = await run_restic(repo, "snapshots", "--tag", TAG, "--json", "--no-lock")
        if snaps.returncode == 10 or (snaps.ok and not parse_snapshots(snaps.stdout)):
            settings.config_backup_maintenance_at = datetime.now(UTC)
            settings.config_backup_maintenance_error = None
            await db.commit()
            return None
        forget = await run_restic(
            repo,
            "forget", "--tag", TAG, "--group-by", "host",
            *keep_args(settings),
            "--prune", "--retry-lock", RETRY_LOCK,
            timeout=RESTIC_TIMEOUT_SECONDS,
        )
        if not forget.ok:
            error = f"forget: {forget.error()}"
        else:
            check = await run_restic(
                repo, "check", "--retry-lock", RETRY_LOCK, timeout=RESTIC_TIMEOUT_SECONDS
            )
            if not check.ok:
                error = f"check: {check.error()}"
    except ConfigBackupError as exc:
        error = exc.detail or exc.key
    settings.config_backup_maintenance_at = datetime.now(UTC)
    settings.config_backup_maintenance_error = error[:1000] if error else None
    await db.commit()
    if error:
        logger.warning("Configuration backup maintenance failed: %s", error)
    return error

