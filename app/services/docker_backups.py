"""restic backups of Docker volumes and host paths (`DockerBackup`):
checking the form, and the restic settings a job runs with
(`app.ssh.restic`).

The repository address, its password and the extra environment are
encrypted at rest and never shown again in full — the address only as
`repository_display` (credentials in it redacted). Leaving the password
or environment empty on edit keeps what is stored.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.docker import DockerBackup
from app.db.models.machine import Machine
from app.ssh.docker_cli import DockerCommandError, is_volume_name_valid
from app.ssh.restic import (
    MAX_SOURCES,
    ResticConfig,
    is_repository_valid,
    normalize_host_path,
    parse_env_lines,
    redact_repository,
)

MAX_KEEP = 10_000
_NAME_MAX = 64


async def list_backups(db: AsyncSession, machine_id: uuid.UUID) -> list[DockerBackup]:
    result = await db.execute(
        select(DockerBackup)
        .where(DockerBackup.machine_id == machine_id)
        .order_by(DockerBackup.name)
    )
    return list(result.scalars().all())


async def get_backup(
    db: AsyncSession, machine_id: uuid.UUID, backup_id: uuid.UUID
) -> DockerBackup | None:
    backup = await db.get(DockerBackup, backup_id, populate_existing=True)
    return backup if backup is not None and backup.machine_id == machine_id else None


async def name_taken(
    db: AsyncSession, machine_id: uuid.UUID, name: str, exclude: uuid.UUID | None = None
) -> bool:
    query = select(DockerBackup.id).where(
        DockerBackup.machine_id == machine_id, DockerBackup.name == name
    )
    if exclude is not None:
        query = query.where(DockerBackup.id != exclude)
    return (await db.execute(query.limit(1))).first() is not None


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _keep(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    if not value.isdigit() or not 0 < int(value) <= MAX_KEEP:
        raise ValueError(value)
    return int(value)


@dataclass
class BackupForm:
    name: str
    repository: str
    # Empty on edit = keep the stored one.
    password: str
    env: str
    volumes: str
    paths: str
    excludes: str
    stop_containers: bool = False
    enabled: bool = True
    keep_last: str = ""
    keep_daily: str = ""
    keep_weekly: str = ""
    keep_monthly: str = ""
    errors: list[str] = field(default_factory=list)

    _parsed: dict[str, object] = field(default_factory=dict, init=False, repr=False)

    def validate(self, *, existing: DockerBackup | None) -> list[str]:
        errors: list[str] = []
        self.name = self.name.strip()
        if not self.name or len(self.name) > _NAME_MAX or any(c in self.name for c in "\n\r\0"):
            errors.append("docker.backup.error.name")
        repository = self.repository.strip()
        if (repository or existing is None) and not is_repository_valid(repository):
            errors.append("docker.backup.error.repository")
        if existing is None and not self.password:
            errors.append("docker.backup.error.password")
        if self.password and any(c in self.password for c in "\n\r\0"):
            errors.append("docker.backup.error.password")
        if self.env.strip():
            try:
                parse_env_lines(self.env)
            except DockerCommandError:
                errors.append("docker.backup.error.env")
        volumes = _lines(self.volumes)
        if any(not is_volume_name_valid(v) for v in volumes):
            errors.append("docker.backup.error.volumes")
        paths: list[str] = []
        for raw in _lines(self.paths):
            normalized = normalize_host_path(raw)
            if normalized is None:
                errors.append("docker.backup.error.paths")
                break
            paths.append(normalized)
        if not volumes and not paths:
            errors.append("docker.backup.error.nothing")
        if len(volumes) + len(paths) > MAX_SOURCES:
            errors.append("docker.backup.error.too_many")
        excludes = _lines(self.excludes)
        if any(len(e) > 512 or "\0" in e for e in excludes):
            errors.append("docker.backup.error.excludes")
        keep: dict[str, int | None] = {}
        for key in ("last", "daily", "weekly", "monthly"):
            try:
                keep[key] = _keep(getattr(self, f"keep_{key}"))
            except ValueError:
                errors.append("docker.backup.error.keep")
                break
        self._parsed = {
            "repository": repository,
            "volumes": sorted(set(volumes)),
            "paths": sorted(set(paths)),
            "excludes": excludes,
            "keep": keep,
        }
        self.errors = errors
        return errors

    @property
    def volume_list(self) -> list[str]:
        volumes = self._parsed.get("volumes")
        return [str(v) for v in volumes] if isinstance(volumes, list) else []

    def apply(self, backup: DockerBackup) -> None:
        """Copy onto `backup` (call `validate` first)."""
        parsed = self._parsed
        backup.name = self.name
        repository = str(parsed["repository"])
        if repository:
            backup.repository_encrypted = encrypt_secret(repository)
            backup.repository_display = redact_repository(repository)[:512]
        if self.password:
            backup.password_encrypted = encrypt_secret(self.password)
        if self.env.strip():
            backup.env_encrypted = encrypt_secret(self.env)
        backup.volumes = list(parsed["volumes"])  # type: ignore[call-overload]
        backup.paths = list(parsed["paths"])  # type: ignore[call-overload]
        backup.excludes = list(parsed["excludes"])  # type: ignore[call-overload]
        backup.stop_containers = self.stop_containers
        backup.enabled = self.enabled
        keep: dict[str, int | None] = parsed["keep"]  # type: ignore[assignment]
        backup.keep_last = keep.get("last")
        backup.keep_daily = keep.get("daily")
        backup.keep_weekly = keep.get("weekly")
        backup.keep_monthly = keep.get("monthly")


def keep_of(backup: DockerBackup) -> dict[str, int | None]:
    return {
        "last": backup.keep_last,
        "daily": backup.keep_daily,
        "weekly": backup.keep_weekly,
        "monthly": backup.keep_monthly,
    }


def has_retention(backup: DockerBackup) -> bool:
    return any(keep_of(backup).values())


def config_for(
    backup: DockerBackup,
    machine: Machine,
    *,
    volumes: list[str] | None = None,
    paths: list[str] | None = None,
) -> ResticConfig:
    """The restic settings of `backup` — `volumes` / `paths` narrow a
    restore to part of it."""
    env = decrypt_secret(backup.env_encrypted) if backup.env_encrypted else ""
    chosen_volumes = list(backup.volumes or [])
    chosen_paths = list(backup.paths or [])
    if volumes is not None or paths is not None:
        chosen_volumes = [v for v in chosen_volumes if v in (volumes or [])]
        chosen_paths = [p for p in chosen_paths if p in (paths or [])]
    return ResticConfig(
        backup_id=str(backup.id),
        host=machine.name,
        repository=decrypt_secret(backup.repository_encrypted),
        password=decrypt_secret(backup.password_encrypted),
        env=parse_env_lines(env),
        volumes=chosen_volumes,
        paths=chosen_paths,
        excludes=list(backup.excludes or []),
    )
