"""Scheduled full backups, kept on the data volume.

Backup & restore → "Automatic backups": the same passphrase-encrypted file
`app.services.full_backup` writes for a manual download, made every N
hours by `app.tasks.jobs.run_due_app_backup` and stored under
`<SSH_DATA_DIR>/backups` (the volume the web, worker and beat containers
share), newest N kept. The passphrase is stored encrypted in `AppSettings`
— needed to write a backup unattended, never shown again.

This protects against a bad change or a broken database, not against
losing the host: the files sit next to the application. Copy them off the
machine (the REST API lists and serves them) for that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import decrypt_secret
from app.db.models.app_settings import AppSettings
from app.services import full_backup

BACKUP_DIR_NAME = "backups"
MIN_INTERVAL_HOURS = 1
MAX_INTERVAL_HOURS = 24 * 31
MIN_KEEP = 1
MAX_KEEP = 365

# Exactly what `full_backup.backup_filename` produces — a name that doesn't
# match is never opened, so a request can't reach outside the directory.
_NAME = re.compile(
    rf"^{full_backup.APP_NAME}-backup-(\d{{8}}T\d{{6}}Z)\.{full_backup.FILE_EXTENSION}$"
)


@dataclass(frozen=True)
class StoredBackup:
    name: str
    size: int
    created_at: datetime


def backup_dir() -> Path:
    return get_settings().ssh_data_dir / BACKUP_DIR_NAME


def _created_at(name: str) -> datetime | None:
    match = _NAME.match(name)
    if match is None:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def list_backups() -> list[StoredBackup]:
    """Stored backups, newest first."""
    directory = backup_dir()
    if not directory.is_dir():
        return []
    found: list[StoredBackup] = []
    for path in directory.iterdir():
        created_at = _created_at(path.name)
        if created_at is None or not path.is_file():
            continue
        found.append(StoredBackup(path.name, path.stat().st_size, created_at))
    return sorted(found, key=lambda backup: backup.created_at, reverse=True)


def backup_path(name: str) -> Path | None:
    """The stored file called `name`, or None when there is no such backup."""
    if _created_at(name) is None:
        return None
    path = backup_dir() / name
    return path if path.is_file() else None


def delete_backup(name: str) -> bool:
    path = backup_path(name)
    if path is None:
        return False
    path.unlink()
    return True


def prune(keep: int) -> list[str]:
    """Remove all but the newest `keep` backups; returns the removed names."""
    removed: list[str] = []
    for backup in list_backups()[max(keep, MIN_KEEP) :]:
        (backup_dir() / backup.name).unlink(missing_ok=True)
        removed.append(backup.name)
    return removed


def is_due(app_settings: AppSettings, now: datetime) -> bool:
    if not app_settings.auto_backup_enabled or not app_settings.auto_backup_passphrase_encrypted:
        return False
    last = app_settings.auto_backup_last_at
    if last is None:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return now - last >= timedelta(hours=app_settings.auto_backup_interval_hours)


async def run_backup(db: AsyncSession, app_settings: AppSettings, now: datetime) -> StoredBackup:
    """Write one backup into the backup directory and prune the old ones.
    Raises `full_backup.BackupError` when no passphrase is stored."""
    if not app_settings.auto_backup_passphrase_encrypted:
        raise full_backup.BackupError("No passphrase is set for automatic backups.")
    passphrase = decrypt_secret(app_settings.auto_backup_passphrase_encrypted)
    directory = backup_dir()
    directory.mkdir(parents=True, exist_ok=True)
    name = full_backup.backup_filename(now)
    # Written under another name first: a half-written file never looks
    # like a backup to `list_backups` or to someone copying the directory.
    partial = directory / f"{name}.part"
    try:
        with partial.open("wb") as destination:
            await full_backup.write_backup(db, destination, passphrase)
        partial.replace(directory / name)
    finally:
        partial.unlink(missing_ok=True)
    prune(app_settings.auto_backup_keep)
    return StoredBackup(name, (directory / name).stat().st_size, now.replace(microsecond=0))
