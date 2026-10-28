"""Docker on a managed machine, beyond what a monitoring sample reports
(`Machine.docker_*`): the work debcontrol does there and what it keeps
about it. See wiki/Docker for the whole feature.

- `DockerJob` — one long operation on one machine (update or roll back a
  container, deploy or sync a stack, scan images, clean up, a restic
  backup, check, prune or restore). It runs detached on the machine
  (`app.ssh.detached_jobs`), so it finishes even when debcontrol itself
  restarts in the middle — for instance because the container being
  updated runs on debcontrol's own host. Kept for `docker_jobs.KEEP_DAYS`.
- `DockerImageScan` — the latest vulnerability scan (Trivy and Grype) of
  one image on one machine, keyed by the image's id: a new scan of the
  same image replaces it, and a changed image gets its own.
- `DockerImageFinding` — the critical and high findings of each stored
  scan, one row each, so the fleet can be asked "which machines and
  images have CVE-…" with an index instead of reading every scan.
- `DockerVulnerabilityAcceptance` — a critical or high vulnerability an
  admin accepted until a date (for every image, or one image
  repository): left out of the counts, the gate and alerts until then.
- `DockerContainerSetting` — per container: updated automatically by the
  "Update Docker containers" schedule or not, how far such an update may
  go (`UpdatePolicy`), and which vulnerabilities stop an update.
- `DockerStack` — a Compose stack debcontrol deploys itself, written in
  debcontrol or taken from a Git repository. Stacks debcontrol finds on a
  machine without having deployed them are read live, not stored.
- `DockerStackVersion` — what a stack looked like each time it was
  deployed (when the stack keeps a history), to roll back to.
- `DockerBackup` — a restic backup of Docker volumes and host paths,
  run in restic's own container on the machine.

Secrets (Git tokens, `.env` files, restic passwords and repository
credentials) are stored with `app.core.security.encrypt_secret` and never
shown again in full; webhook tokens only as their SHA-256.

Kinds and statuses are plain strings checked against the `StrEnum`s below
rather than Postgres enum types, so a new kind needs no migration.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    false,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class DockerJobKind(enum.StrEnum):
    CONTAINER_UPDATE = "container_update"
    CONTAINER_ROLLBACK = "container_rollback"
    STACK_ACTION = "stack_action"
    STACK_DEPLOY = "stack_deploy"
    # Check a stack before deploying it: the differences and `docker compose config`.
    STACK_CHECK = "stack_check"
    IMAGE_SCAN = "image_scan"
    PRUNE = "prune"
    BACKUP_RUN = "backup_run"
    BACKUP_CHECK = "backup_check"
    BACKUP_FORGET = "backup_forget"
    BACKUP_RESTORE = "backup_restore"
    # Restore the newest snapshot into a temporary volume, verify it, remove it.
    BACKUP_VERIFY = "backup_verify"


class DockerJobStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    # An update the vulnerability gate stopped; nothing was changed.
    BLOCKED = "blocked"
    # Nothing to do (the image was already the newest).
    SKIPPED = "skipped"
    # Stopped on request (`DockerJob.cancel_requested_by`).
    CANCELLED = "cancelled"


class DockerJob(Base):
    __tablename__ = "docker_jobs"
    __table_args__ = (
        Index("ix_docker_jobs_machine_created", "machine_id", "created_at"),
        Index("ix_docker_jobs_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=DockerJobStatus.PENDING.value
    )
    # What it acts on: a container, a stack, an image, a backup's name.
    target: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # The request (gate policy, prune options, snapshot id, ...).
    params: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # What came out (image ids before/after, gate verdict, bytes freed, ...).
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # The tail of the output (`docker_jobs.MAX_OUTPUT_CHARS`).
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    started_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Jobs started together (an "Update all", a schedule firing).
    batch_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    # A related object (`DockerStack.id`, `DockerBackup.id`), when there is one.
    ref_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    # When debcontrol last read the job's state on the machine.
    heartbeat_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # Someone asked a running job to stop; the worker following it signals
    # the job on the machine and closes it as cancelled.
    cancel_requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"DockerJob(id={self.id!r}, kind={self.kind!r}, status={self.status!r})"


class DockerImageScan(Base):
    __tablename__ = "docker_image_scans"
    __table_args__ = (
        UniqueConstraint("machine_id", "image_id", name="uq_docker_image_scans_machine_image"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    # `sha256:...` — what the scan is cached by.
    image_id: Mapped[str] = mapped_column(String(80), nullable=False)
    # The reference it was scanned as (`nginx:1.27`), for display.
    image_ref: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    # Which scanners answered, with their versions: {"trivy": "0.58.1", ...}.
    scanners: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    # {"critical": 2, "high": 10, "medium": 31, "low": 4, "unknown": 0} —
    # without accepted vulnerabilities (`DockerVulnerabilityAcceptance`),
    # which is what the gate, summaries and alerts read.
    counts: Mapped[dict[str, int] | None] = mapped_column(JSON, nullable=True)
    # What the scanners found, accepted ones included; None = same as
    # `counts` (no acceptance applied yet, or a scan from before 0.125.0).
    raw_counts: Mapped[dict[str, int] | None] = mapped_column(JSON, nullable=True)
    # [{"id", "pkg", "installed", "fixed", "severity", "title", "url",
    #   "scanners": [...]}], most severe first (`docker_scan.MAX_FINDINGS`).
    vulnerabilities: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # {"grype": "error text"} for a scanner that failed.
    errors: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)


class DockerImageFinding(Base):
    """One critical or high finding of a stored scan (`DockerImageScan.
    vulnerabilities` keeps them all); replaced with the scan."""

    __tablename__ = "docker_image_findings"
    __table_args__ = (
        Index("ix_docker_image_findings_vuln", "vuln_id"),
        Index("ix_docker_image_findings_scan", "scan_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("docker_image_scans.id", ondelete="CASCADE"), nullable=False
    )
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    # CVE-2026-1234, GHSA-..., as the scanner named it.
    vuln_id: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    pkg: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    installed: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    fixed: Mapped[str] = mapped_column(String(255), nullable=False, default="")


class DockerVulnerabilityAcceptance(Base):
    """A vulnerability accepted until `expires_at` (`app.services.
    docker_acceptances`): fleet-wide, for every image (`image` == "") or
    for one image repository (`image_versions.repository_key`, e.g.
    "docker.io/library/nginx"). Removed once it has expired and the
    counts have been put back."""

    __tablename__ = "docker_vulnerability_acceptances"
    __table_args__ = (
        UniqueConstraint("vuln_id", "image", name="uq_docker_vuln_acceptances_vuln_image"),
        Index("ix_docker_vuln_acceptances_expires", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    vuln_id: Mapped[str] = mapped_column(String(128), nullable=False)
    image: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    reason: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)


class UpdatePolicy(enum.StrEnum):
    """How far an automatic (scheduled) update of a container may go,
    judged by semantic versions (`app.services.update_policy`)."""

    # Whatever the registry has under the tag (what every container did
    # before 0.125.0).
    ANY = "any"
    # Within the same major version (1.4 -> 1.5, never 1.x -> 2.0).
    MINOR = "minor"
    # Within the same major.minor version (1.4.2 -> 1.4.3 only).
    PATCH = "patch"


class VulnerabilityGate(enum.StrEnum):
    """What stops an update (`app.services.docker_gate`)."""

    OFF = "off"
    # The new image has a critical vulnerability.
    CRITICAL = "critical"
    # The new image has a critical or high one.
    HIGH = "high"
    # The new image has more critical + high ones than the running image.
    WORSE = "worse"


class DockerContainerSetting(Base):
    __tablename__ = "docker_container_settings"
    __table_args__ = (
        UniqueConstraint("machine_id", "name", name="uq_docker_container_settings_machine_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    # The container's name (for a Compose service, its container's name).
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    auto_update: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    vulnerability_gate: Mapped[str] = mapped_column(
        String(16), nullable=False, default=VulnerabilityGate.OFF.value
    )
    # `UpdatePolicy`: applies to automatic (scheduled) updates.
    update_policy: Mapped[str] = mapped_column(
        String(16), nullable=False, default=UpdatePolicy.ANY.value, server_default="any"
    )
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )


class StackSource(enum.StrEnum):
    # Written in debcontrol (compose file and .env).
    EDITOR = "editor"
    # Taken from a Git repository: HTTPS (optionally with a token) or SSH
    # with a deploy key.
    GIT = "git"


class DockerStack(Base):
    __tablename__ = "docker_stacks"
    __table_args__ = (
        UniqueConstraint("machine_id", "name", name="uq_docker_stacks_machine_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    # The Compose project name (`docker_cli.is_project_name_valid`).
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    # Where the stack's files are on the machine, chosen when it was made
    # (`docker_compose.normalize_stack_directory`); None = the default
    # `~/.local/share/debcontrol/stacks/<name>`.
    directory: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # Editor: the compose file. Git: the compose file deployed last.
    compose_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The `.env` file, encrypted.
    env_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    git_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    git_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # The compose file's path inside the repository.
    git_compose_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    git_token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # More compose files from the repository, applied after the first one in
    # this order (overrides), e.g. ["compose.prod.yaml"]. None = just one.
    git_compose_overrides: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    # SSH deploy key (an OpenSSH private key, encrypted) for an SSH
    # repository address, and its public half to show and add to the
    # repository host.
    git_ssh_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    git_ssh_public_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # The repository host's SSH key(s), known_hosts lines: pasted by the
    # admin, or recorded on the first connection and required from then on.
    git_known_hosts: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Check the branch for new commits every few minutes and deploy them.
    auto_sync: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # SHA-256 of the webhook token (`/hooks/docker/<token>`); None = no webhook.
    webhook_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True
    )
    webhook_last_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # Opt-in safety for deploys (all off for an existing stack):
    # keep each deployed version to roll back to (`DockerStackVersion`) …
    keep_history: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    # … put the previous version back when the containers don't come up
    # (exit, restart loop, unhealthy) after a deploy …
    auto_rollback: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    # … and scan new images before `up`, stopping the deploy like the
    # container update gate (`VulnerabilityGate`).
    vulnerability_gate: Mapped[str] = mapped_column(
        String(16), nullable=False, default="off", server_default="off"
    )

    # What is on the machine now.
    deployed_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # SHA-256 of the compose file and .env deployed, to tell "changed since".
    deployed_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    deployed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # Written in debcontrol: the compose file and `.env` (encrypted) deployed
    # last, to show what a deploy would change. None before 0.124.0.
    deployed_compose: Mapped[str | None] = mapped_column(Text, nullable=True)
    deployed_env_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)

    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )


class DockerStackVersion(Base):
    """One deployed version of a stack that keeps a history: everything
    needed to deploy exactly it again (secrets encrypted like the stack's
    own). The newest `docker_stacks.HISTORY_LIMIT` are kept per stack."""

    __tablename__ = "docker_stack_versions"
    __table_args__ = (Index("ix_docker_stack_versions_stack_created", "stack_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    stack_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("docker_stacks.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    compose_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    env_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    git_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    git_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    git_compose_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    git_compose_overrides: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    deployed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)


class DockerBackup(Base):
    __tablename__ = "docker_backups"
    __table_args__ = (
        UniqueConstraint("machine_id", "name", name="uq_docker_backups_machine_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # The restic repository (`/srv/backup`, `s3:...`, `rest:...`): may carry
    # credentials, so encrypted, with a redacted copy for display.
    repository_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    repository_display: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    password_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Extra environment for the repository (`AWS_ACCESS_KEY_ID=...`), encrypted.
    env_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    volumes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    paths: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    excludes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    # Stop the containers using the volumes while the backup runs.
    stop_containers: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # List every snapshot in the repository, not just this backup's: for a
    # repository brought over from another machine or an older install.
    all_snapshots: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    keep_last: Mapped[int | None] = mapped_column(Integer, nullable=True)
    keep_daily: Mapped[int | None] = mapped_column(Integer, nullable=True)
    keep_weekly: Mapped[int | None] = mapped_column(Integer, nullable=True)
    keep_monthly: Mapped[int | None] = mapped_column(Integer, nullable=True)

    last_backup_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_backup_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_backup_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_check_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_check_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Commands run with `docker exec` in `hook_container` before the backup
    # (a database dump: a non-zero exit stops the backup) and after it,
    # whether it succeeded or not (removing the dump). Edited only with
    # `action.terminal`, like the container shell.
    hook_container: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pre_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    post_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The last test restore (`DockerJobKind.BACKUP_VERIFY`): "ok" / "failed",
    # with the snapshot it restored and what was found.
    last_verify_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_verify_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_verify_details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )
