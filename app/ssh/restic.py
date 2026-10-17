"""restic backups of Docker volumes and host paths, run in restic's own
container on the machine (`docker_cli.RESTIC_IMAGE`, pulled fresh for
every job) — nothing to install, and through the Docker grant it reads
every file it is asked to back up.

**What is backed up.** Each volume is mounted read-only at
`/backup/volumes/<name>`, each host path at `/backup/paths/<path>`, and
restic backs up `/backup`, tagged `debcontrol` and `dc-<backup id>` and
recorded under the machine's name as host. A restore mounts the same
places writable and restores the snapshot onto them, so files go back
where they came from; files created since the snapshot stay unless the
restore is asked to delete them.

**Consistency.** A backup can stop the containers using its volumes for
its duration (a database's files are only consistent while it is
stopped); a restore always does. They are started again when the job
ends, whether it succeeded or not.

**Secrets.** The repository address, its password and any extra
environment (S3 keys...) reach restic through an `--env-file` written with
mode 600 in a temporary file the job removes on exit; the job script
itself is only ever sent on standard input (`app.ssh.detached_jobs`).

**Repositories.** A local path on the machine (mounted into the
container) or one of restic's remote backends that need nothing but
environment variables: `s3:`, `b2:`, `azure:`, `gs:`, `swift:`, `rest:`.
`sftp:` and `rclone:` would need keys or configuration inside the
container and are not offered.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from app.ssh.docker_cli import (
    HELPER_LABEL,
    RESTIC_IMAGE,
    DockerCommandError,
    as_dict,
    is_volume_name_valid,
    q,
)

RESTIC_CACHE_VOLUME = "debcontrol-restic-cache"
REMOTE_PREFIXES = ("s3:", "b2:", "azure:", "gs:", "swift:", "rest:")
MAX_SOURCES = 50

_ENV_KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
_RESERVED_ENV = {"RESTIC_REPOSITORY", "RESTIC_PASSWORD", "RESTIC_CACHE_DIR"}
_SNAPSHOT_RE = re.compile(r"^([0-9a-f]{8,64}|latest)$")


def is_snapshot_valid(snapshot: str) -> bool:
    return bool(_SNAPSHOT_RE.match(snapshot))
_HOST_RE = re.compile(r"[^A-Za-z0-9._-]")
# Never backed up or restored onto: the machine's own runtime filesystems.
_FORBIDDEN_PATHS = ("/", "/proc", "/sys", "/dev", "/run")


def is_repository_valid(repository: str) -> bool:
    if not repository or len(repository) > 1024 or any(c in repository for c in "\n\r\0'\""):
        return False
    if repository.startswith("/"):
        return ":" not in repository and posixpath.normpath(repository) not in _FORBIDDEN_PATHS
    return repository.startswith(REMOTE_PREFIXES)


def redact_repository(repository: str) -> str:
    """The address to show: credentials in a `rest:https://user:pass@host`
    replaced by `***`."""
    if repository.startswith("rest:"):
        rest = repository[len("rest:") :]
        try:
            parts = urlsplit(rest)
        except ValueError:
            return "rest:***"
        if parts.username or parts.password:
            host = parts.hostname or ""
            netloc = "***@" + host + (f":{parts.port}" if parts.port else "")
            return "rest:" + urlunsplit(parts._replace(netloc=netloc))
    return repository


def normalize_host_path(path: str) -> str | None:
    """An absolute host path that may be backed up, or None."""
    if not path or any(c in path for c in "\n\r\0:") or len(path) > 1024:
        return None
    if not path.startswith("/"):
        return None
    normalized = "/" + posixpath.normpath(path).lstrip("/")
    if normalized in _FORBIDDEN_PATHS or any(
        normalized.startswith(prefix + "/") for prefix in _FORBIDDEN_PATHS[1:]
    ):
        return None
    return normalized


def parse_env_lines(text: str) -> list[str]:
    """`KEY=value` lines for the repository (S3 keys, ...); raises
    `DockerCommandError` for a malformed or reserved one."""
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, _value = line.partition("=")
        if not sep or not _ENV_KEY_RE.match(key) or key in _RESERVED_ENV or "\0" in line:
            raise DockerCommandError(f'"{key or line[:40]}" is not a valid variable.')
        lines.append(line)
    return lines


@dataclass(frozen=True)
class ResticConfig:
    backup_id: str
    host: str
    repository: str
    password: str
    env: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)

    @property
    def tag(self) -> str:
        return f"dc-{self.backup_id}"

    def validate(self) -> None:
        if not re.match(r"^[0-9a-f-]{36}$", self.backup_id):
            raise DockerCommandError("Invalid backup id.")
        if not is_repository_valid(self.repository):
            raise DockerCommandError("Invalid repository.")
        if not self.password or any(c in self.password for c in "\n\r\0"):
            raise DockerCommandError("Invalid repository password.")
        if len(self.volumes) + len(self.paths) > MAX_SOURCES:
            raise DockerCommandError("Too many volumes and paths.")
        for volume in self.volumes:
            if not is_volume_name_valid(volume):
                raise DockerCommandError(f'"{volume}" is not a valid volume name.')
        for path in self.paths:
            if normalize_host_path(path) != path:
                raise DockerCommandError(f'"{path}" can\'t be backed up.')
        for pattern in self.excludes:
            if not pattern or any(c in pattern for c in "\n\r\0") or len(pattern) > 512:
                raise DockerCommandError("Invalid exclude pattern.")
        for line in self.env:
            parse_env_lines(line)

    @property
    def restic_host(self) -> str:
        return _HOST_RE.sub("-", self.host)[:64] or "debcontrol"


def _env_file(config: ResticConfig) -> str:
    lines = [
        f"RESTIC_REPOSITORY={config.repository}",
        f"RESTIC_PASSWORD={config.password}",
        "RESTIC_CACHE_DIR=/cache",
        *config.env,
    ]
    content = "\n".join(lines) + "\n"
    if "DC_RESTIC_ENV_END" in content:
        raise DockerCommandError("Invalid repository settings.")
    return content


def _mounts(config: ResticConfig, *, writable: bool) -> str:
    mode = "" if writable else ":ro"
    parts = [f"-v {q(v)}:{q('/backup/volumes/' + v)}{mode}" for v in config.volumes]
    parts += [f"-v {q(p)}:{q('/backup/paths' + p)}{mode}" for p in config.paths]
    if config.repository.startswith("/"):
        parts.append(f"-v {q(config.repository)}:{q(config.repository)}")
    return " ".join(parts)


def _prelude(config: ResticConfig, *, mounts: str) -> list[str]:
    config.validate()
    return [
        "set -u",
        "umask 077",
        'renv="$(mktemp)"',
        "stopped=",
        # Containers stopped for the job are started again however it ends.
        'cleanup() { rm -f "$renv"; [ -z "$stopped" ] || { echo "@@DC_STEP start"; '
        "$D start $stopped >/dev/null; }; }",
        "trap cleanup EXIT",
        f"cat > \"$renv\" <<'DC_RESTIC_ENV_END'\n{_env_file(config)}DC_RESTIC_ENV_END",
        f"$D pull -q {RESTIC_IMAGE} >/dev/null 2>&1 || true",
        f'R() {{ $D run --rm --pull missing --label {HELPER_LABEL} --user 0:0 '
        f'--env-file "$renv" -v {RESTIC_CACHE_VOLUME}:/cache {mounts} {RESTIC_IMAGE} "$@"; }}',
    ]


def _stop_users(config: ResticConfig) -> list[str]:
    """Stop the running containers that use the job's volumes; their ids
    go into `$stopped` for `cleanup`."""
    if not config.volumes:
        return []
    filters = " ".join(f"--filter volume={q(v)}" for v in config.volumes)
    lines = ["echo '@@DC_STEP stop'"]
    # `docker ps` ORs filters of the same kind, so one call covers them all.
    lines.append(f'stopped="$($D ps -q {filters} | tr "\\n" " ")"')
    lines.append('[ -z "$stopped" ] || $D stop $stopped >/dev/null || exit 1')
    return lines


def _keep_flags(keep: dict[str, int | None]) -> str:
    flags = []
    for key in ("last", "daily", "weekly", "monthly"):
        value = keep.get(key)
        if value:
            flags.append(f"--keep-{key} {int(value)}")
    return " ".join(flags)


def build_backup_script(
    config: ResticConfig, *, stop_containers: bool, keep: dict[str, int | None]
) -> str:
    if not config.volumes and not config.paths:
        raise DockerCommandError("Nothing to back up.")
    lines = _prelude(config, mounts=_mounts(config, writable=False))
    lines += [
        "echo '@@DC_STEP init'",
        "R cat config >/dev/null 2>&1 || R init || { echo '@@DC_FAILED init'; exit 1; }",
    ]
    if stop_containers:
        lines += _stop_users(config)
    excludes = " ".join(f"--exclude {q(e)}" for e in config.excludes)
    lines += [
        "echo '@@DC_STEP backup'",
        f"R backup /backup --json --quiet --host {q(config.restic_host)} --tag debcontrol "
        f"--tag {q(config.tag)} {excludes} || {{ echo '@@DC_FAILED backup'; exit 1; }}",
    ]
    if stop_containers:
        lines += ['[ -z "$stopped" ] || { echo "@@DC_STEP start"; $D start $stopped >/dev/null; }',
                  "stopped="]
    flags = _keep_flags(keep)
    if flags:
        lines += [
            "echo '@@DC_STEP forget'",
            f"R forget --tag {q(config.tag)} {flags} --prune || {{ echo '@@DC_FAILED forget'; "
            "exit 1; }",
        ]
    lines.append("echo '@@DC_DONE'")
    return "\n".join(lines) + "\n"


def build_check_script(config: ResticConfig, *, read_data_percent: int = 0) -> str:
    lines = _prelude(config, mounts=_mounts(config, writable=False))
    subset = ""
    if 0 < read_data_percent <= 100:
        subset = f" --read-data-subset={int(read_data_percent)}%"
    lines += [
        "echo '@@DC_STEP check'",
        f"R check{subset} || {{ echo '@@DC_FAILED check'; exit 1; }}",
        "echo '@@DC_DONE'",
    ]
    return "\n".join(lines) + "\n"


def build_forget_script(config: ResticConfig, *, keep: dict[str, int | None]) -> str:
    flags = _keep_flags(keep)
    if not flags:
        raise DockerCommandError("No retention set.")
    lines = _prelude(config, mounts=_mounts(config, writable=False))
    lines += [
        "echo '@@DC_STEP forget'",
        f"R forget --tag {q(config.tag)} {flags} --prune || {{ echo '@@DC_FAILED forget'; "
        "exit 1; }",
        "echo '@@DC_DONE'",
    ]
    return "\n".join(lines) + "\n"


def build_restore_script(config: ResticConfig, snapshot: str, *, delete: bool) -> str:
    """Restore `snapshot` onto the backup's volumes and paths (those in
    `config`; a subset restores only those). Always stops the containers
    using the volumes first."""
    if not _SNAPSHOT_RE.match(snapshot):
        raise DockerCommandError("Invalid snapshot.")
    if not config.volumes and not config.paths:
        raise DockerCommandError("Nothing to restore.")
    includes = [f"/backup/volumes/{v}" for v in config.volumes]
    includes += [f"/backup/paths{p}" for p in config.paths]
    lines = _prelude(config, mounts=_mounts(config, writable=True))
    lines += _stop_users(config)
    include_flags = " ".join(f"--include {q(i)}" for i in includes)
    delete_flag = " --delete" if delete else ""
    lines += [
        "echo '@@DC_STEP restore'",
        f"R restore {q(snapshot)} --target / {include_flags}{delete_flag} "
        "|| { echo '@@DC_FAILED restore'; exit 1; }",
        "echo '@@DC_DONE'",
    ]
    return "\n".join(lines) + "\n"


def build_snapshots_script(config: ResticConfig) -> str:
    """List the backup's snapshots (`restic snapshots --json`), quick enough
    to wait for."""
    lines = _prelude(config, mounts=_mounts(config, writable=False))
    lines += [f"R snapshots --json --tag {q(config.tag)}"]
    return "\n".join(lines) + "\n"


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


@dataclass
class BackupSummary:
    snapshot_id: str = ""
    bytes_added: int | None = None
    bytes_processed: int | None = None
    files: int | None = None


def parse_backup_summary(raw: str) -> BackupSummary:
    """The `summary` message `restic backup --json` prints last."""
    summary = BackupSummary()
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{") or '"summary"' not in line:
            continue
        try:
            data = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(data, dict) or data.get("message_type") != "summary":
            continue
        snapshot = str(data.get("snapshot_id") or "")
        summary.snapshot_id = snapshot if _SNAPSHOT_RE.match(snapshot) else ""

        summary.bytes_added = _int(data.get("data_added"))
        summary.bytes_processed = _int(data.get("total_bytes_processed"))
        files = [_int(data.get(k)) for k in ("files_new", "files_changed", "files_unmodified")]
        summary.files = sum(f for f in files if f is not None) if any(files) else None
    return summary


def parse_snapshots(raw: str) -> list[dict[str, Any]]:
    """`restic snapshots --json`: newest first. Never raises."""
    start = raw.find("[")
    if start < 0:
        return []
    try:
        data = json.loads(raw[start : raw.rfind("]") + 1])
    except (ValueError, RecursionError):
        return []
    snapshots: list[dict[str, Any]] = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        snapshot_id = str(item.get("id") or "")
        if not _SNAPSHOT_RE.match(snapshot_id):
            continue
        summary = as_dict(item.get("summary"))
        size = summary.get("total_bytes_processed")
        snapshots.append(
            {
                "id": snapshot_id,
                "short_id": str(item.get("short_id") or snapshot_id[:8])[:16],
                "time": str(item.get("time") or "")[:40],
                "host": str(item.get("hostname") or "")[:64],
                "paths": [str(p)[:1024] for p in item.get("paths") or [] if isinstance(p, str)][
                    :MAX_SOURCES
                ],
                "size_bytes": _int(size),
            }
        )
    snapshots.sort(key=lambda s: s["time"], reverse=True)
    return snapshots


def failed_step(raw: str) -> str | None:
    for line in raw.splitlines():
        if line.startswith("@@DC_FAILED "):
            return line[len("@@DC_FAILED ") :].strip()[:32]
    return None
