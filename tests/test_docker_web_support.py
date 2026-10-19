"""Seeding helpers shared by the Docker tab's web tests
(`tests/test_docker_web_*.py`) — a machine with Docker data as the
monitoring sweep stores it, the Docker model rows a page lists, and a
worker's inventory answer shaped like `app.tasks.docker_jobs` returns it.

No tests live here; the module is named like its siblings so the helpers
stay next to the tests that use them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditLogEntry
from app.db.models.docker import (
    DockerBackup,
    DockerImageScan,
    DockerJob,
    DockerJobKind,
    DockerJobStatus,
    DockerStack,
    StackSource,
)
from app.db.models.machine import AuthMethod, Machine
from app.db.models.role import Permission
from app.services import docker_stacks

Factory = async_sessionmaker[AsyncSession]

MACHINE_NAME = "dockerhost"
IMAGE_ID = "sha256:" + "a" * 64
PREVIOUS_IMAGE_ID = "sha256:" + "b" * 64
SNAPSHOT_ID = "0123abcd" * 8

INVENTORY_TASK = "app.tasks.docker_jobs.docker_inventory"
RUN_JOB_TASK = "app.tasks.docker_jobs.run_docker_job"
SYNC_TASK = "app.tasks.docker_jobs.sync_git_stack"
FILES_TASK = "app.tasks.docker_jobs.docker_files"
COMPOSE_FILE_TASK = "app.tasks.docker_jobs.docker_compose_file"
SNAPSHOTS_TASK = "app.tasks.docker_jobs.docker_backup_snapshots"

VIEWER = frozenset({Permission.MACHINE_VIEW})

# Secrets seeded into the rows below — no page may ever show them.
STACK_ENV_SECRET = "DB_PASSWORD=stack-env-secret-value"
GIT_TOKEN_SECRET = "ghp_gitTokenSecretValue123"
BACKUP_PASSWORD_SECRET = "restic-password-secret-value"
BACKUP_ENV_SECRET = "AWS_SECRET_ACCESS_KEY=backup-env-secret-value"
BACKUP_REPO_PASSWORD = "repo-url-password"


async def make_docker_machine(
    db_session_factory: Factory, *, pinned: bool = True, name: str = MACHINE_NAME
) -> uuid.UUID:
    """A machine whose last sweep found Docker with two containers, one of
    them with a newer image available."""
    async with db_session_factory() as session:
        machine = Machine(
            name=name,
            ip_address="10.20.0.5",
            port=22,
            username="root",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint" if pinned else None,
            docker_status="ok",
            docker_containers=[
                {
                    "id": "0f1e2d3c4b5a",
                    "name": "web",
                    "state": "running",
                    "status": "Up 3 hours",
                    "health": "healthy",
                    "image": "nginx:1.27",
                    "ports": "0.0.0.0:80->80/tcp",
                    "compose_project": "site",
                    "cpu_percent": 1.5,
                    "mem_bytes": 52_428_800,
                },
                {
                    "id": "9a8b7c6d5e4f",
                    "name": "worker",
                    "state": "exited",
                    "status": "Exited (1) 2 hours ago",
                    "health": None,
                    "image": "redis:7",
                    "ports": "",
                    "compose_project": "",
                },
            ],
            docker_image_updates={"nginx:1.27": "update", "redis:7": "current"},
            docker_image_versions={
                "nginx:1.27": {"local_version": "1.27.0", "remote_version": "1.27.1"}
            },
            docker_images_checked_at=datetime.now(UTC) - timedelta(hours=1),
        )
        session.add(machine)
        await session.commit()
        return machine.id


async def add_job(
    db_session_factory: Factory,
    machine_id: uuid.UUID,
    *,
    kind: DockerJobKind = DockerJobKind.CONTAINER_UPDATE,
    target: str = "web",
    status: DockerJobStatus = DockerJobStatus.SUCCEEDED,
    result: dict[str, Any] | None = None,
    output: str | None = "Pulling nginx:1.27\nRecreated web\n",
    ref_id: uuid.UUID | None = None,
) -> uuid.UUID:
    finished = status not in (DockerJobStatus.PENDING, DockerJobStatus.RUNNING)
    started = datetime.now(UTC) - timedelta(minutes=5)
    async with db_session_factory() as session:
        job = DockerJob(
            machine_id=machine_id,
            kind=kind,
            status=status,
            target=target,
            params={"gate": "off"},
            result=result,
            output=output,
            started_by="test-admin",
            ref_id=ref_id,
            started_at=started,
            finished_at=started + timedelta(seconds=42) if finished else None,
        )
        session.add(job)
        await session.commit()
        return job.id


async def add_scan(db_session_factory: Factory, machine_id: uuid.UUID) -> None:
    async with db_session_factory() as session:
        session.add(
            DockerImageScan(
                machine_id=machine_id,
                image_id=IMAGE_ID,
                image_ref="nginx:1.27",
                scanners={"trivy": "0.58.1", "grype": "0.86.0"},
                counts={"critical": 1, "high": 2, "medium": 0, "low": 0, "unknown": 0},
                vulnerabilities=[
                    {
                        "id": "CVE-2026-0001",
                        "pkg": "openssl",
                        "installed": "3.0.1",
                        "fixed": "3.0.2",
                        "severity": "critical",
                        "title": "A bad one",
                        "url": "https://example.test/CVE-2026-0001",
                        "scanners": ["trivy", "grype"],
                    },
                    {
                        "id": "CVE-2026-0002",
                        "pkg": "zlib",
                        "installed": "1.2",
                        "fixed": "",
                        "severity": "high",
                        "title": "",
                        "url": "",
                        "scanners": ["grype"],
                    },
                ],
                errors={},
            )
        )
        await session.commit()


async def add_stack(
    db_session_factory: Factory,
    machine_id: uuid.UUID,
    *,
    name: str = "site",
    source: StackSource = StackSource.GIT,
    deployed: bool = True,
    with_webhook: bool = False,
) -> tuple[uuid.UUID, str | None]:
    """A stack with an encrypted .env (and, from Git, a token); returns
    (its id, the raw webhook token when one was made)."""
    token: str | None = None
    async with db_session_factory() as session:
        stack = DockerStack(
            machine_id=machine_id,
            name=name,
            source=source,
            compose_content="services:\n  web:\n    image: nginx:1.27\n",
            env_encrypted=encrypt_secret(STACK_ENV_SECRET),
            created_by="test-admin",
        )
        if source == StackSource.GIT:
            stack.git_url = "https://git.example.test/ops/site.git"
            stack.git_branch = "main"
            stack.git_compose_path = "compose.yaml"
            stack.git_token_encrypted = encrypt_secret(GIT_TOKEN_SECRET)
            stack.auto_sync = True
        if with_webhook:
            token, digest = docker_stacks.new_webhook_token()
            stack.webhook_token_hash = digest
        if deployed:
            stack.deployed_at = datetime.now(UTC) - timedelta(days=1)
            stack.deployed_commit = "c0ffee1234567890"
            stack.last_status = "ok"
        session.add(stack)
        await session.commit()
        return stack.id, token


async def add_backup(
    db_session_factory: Factory,
    machine_id: uuid.UUID,
    *,
    name: str = "nightly",
    keep_daily: int | None = 7,
    stop_containers: bool = False,
) -> uuid.UUID:
    repository = f"rest:https://backup:{BACKUP_REPO_PASSWORD}@restic.example.test/repo"
    async with db_session_factory() as session:
        backup = DockerBackup(
            machine_id=machine_id,
            name=name,
            repository_encrypted=encrypt_secret(repository),
            repository_display="rest:https://***@restic.example.test/repo",
            password_encrypted=encrypt_secret(BACKUP_PASSWORD_SECRET),
            env_encrypted=encrypt_secret(BACKUP_ENV_SECRET),
            volumes=["site_data"],
            paths=["/srv/site/config"],
            excludes=[],
            stop_containers=stop_containers,
            keep_daily=keep_daily,
            last_backup_at=datetime.now(UTC) - timedelta(hours=3),
            last_backup_status="ok",
            last_success_at=datetime.now(UTC) - timedelta(hours=3),
            last_snapshot_id=SNAPSHOT_ID,
            last_backup_bytes=1_048_576,
            created_by="test-admin",
        )
        session.add(backup)
        await session.commit()
        return backup.id


def inventory_answer() -> dict[str, Any]:
    """What `docker_inventory` answers for every section the pages ask for."""
    container = {
        "id": "0f1e2d3c4b5a",
        "name": "web",
        "state": "running",
        "status": "Up 3 hours",
        "running": True,
        "health": "healthy",
        "image": "nginx:1.27",
        "image_id": IMAGE_ID,
        "compose_project": "site",
        "compose_service": "web",
        "compose_working_dir": "/srv/site",
        "compose_config_files": ["/srv/site/compose.yaml"],
        "created": "2026-10-01T10:00:00.000Z",
        "started_at": "2026-10-17T07:00:00.000Z",
        "exit_code": None,
        "restart_policy": "unless-stopped",
        "restart_count": 0,
        "command": "nginx -g 'daemon off;'",
        "network_mode": "site_default",
        "networks": ["site_default"],
        "ports": ["0.0.0.0:80->80/tcp"],
        "env_names": ["DB_PASSWORD", "TZ"],
        "mounts": [
            {
                "type": "volume",
                "name": "site_data",
                "source": "/var/lib/docker/volumes/site_data/_data",
                "destination": "/usr/share/nginx/html",
                "rw": True,
            }
        ],
        "labels": {"com.docker.compose.project": "site"},
        "privileged": False,
    }
    stopped = {
        **container,
        "id": "9a8b7c6d5e4f",
        "name": "worker",
        "state": "exited",
        "status": "Exited (1) 2 hours ago",
        "running": False,
        "compose_project": "",
        "compose_service": "",
        "compose_working_dir": "",
        "compose_config_files": [],
        "exit_code": 1,
        "mounts": [],
        "labels": {},
    }
    return {
        "ok": True,
        "inventory": {
            "containers": [container, stopped],
            "images": [
                {
                    "id": IMAGE_ID,
                    "ref": "nginx:1.27",
                    "size_bytes": 190_000_000,
                    "created": "2026-09-30T12:00:00Z",
                    "in_use": True,
                    "dangling": False,
                    "digest": "sha256:" + "d" * 64,
                },
                {
                    "id": PREVIOUS_IMAGE_ID,
                    "ref": "",
                    "size_bytes": 80_000_000,
                    "created": "2026-08-01T12:00:00Z",
                    "in_use": False,
                    "dangling": True,
                    "digest": "",
                },
            ],
            "df": {
                "images": {
                    "size_bytes": 270_000_000,
                    "reclaimable_bytes": 80_000_000,
                    "total": 2,
                    "active": 1,
                },
                "build_cache": {"size_bytes": 0, "reclaimable_bytes": 0, "total": 0, "active": 0},
            },
            "volumes": [
                {
                    "name": "site_data",
                    "driver": "local",
                    "compose_project": "site",
                    "used_by": ["web"],
                    "anonymous": False,
                    "size_bytes": 4096,
                }
            ],
            "networks": [
                {
                    "name": "site_default",
                    "driver": "bridge",
                    "scope": "local",
                    "containers": ["web"],
                    "builtin": False,
                    "internal": False,
                },
                {
                    "name": "bridge",
                    "driver": "bridge",
                    "scope": "local",
                    "containers": [],
                    "builtin": True,
                    "internal": False,
                },
            ],
            "network_details": [
                {
                    "id": "e" * 64,
                    "name": "site_default",
                    "driver": "bridge",
                    "scope": "local",
                    "created": "2026-10-01T10:00:00.000Z",
                    "internal": False,
                    "attachable": False,
                    "ingress": False,
                    "ipv6": False,
                    "builtin": False,
                    "ipam_driver": "default",
                    "subnets": [
                        {"subnet": "172.18.0.0/16", "gateway": "172.18.0.1", "ip_range": ""}
                    ],
                    "options": {"com.docker.network.bridge.name": "br-site"},
                    "labels": {"com.docker.compose.project": "site"},
                    "compose_project": "site",
                    "containers": [
                        {
                            "id": "0f1e2d3c4b5a",
                            "name": "web",
                            "ipv4": "172.18.0.2/16",
                            "ipv6": "",
                            "mac": "02:42:ac:12:00:02",
                        }
                    ],
                }
            ],
            "compose": [
                {"name": "site", "status": "running(1)", "config_files": ["/srv/site/compose.yaml"]}
            ],
        },
    }


async def csrf_token(client: AsyncClient, machine_id: uuid.UUID) -> str:
    """A CSRF token for `client` — any page of the tab hands one out."""
    response = await client.get(f"/machines/{machine_id}/docker/jobs")
    assert response.status_code == 200
    token = client.cookies.get("csrftoken")
    assert token
    return token


async def audit_entries(db_session_factory: Factory, action: str) -> list[AuditLogEntry]:
    async with db_session_factory() as session:
        result = await session.execute(
            select(AuditLogEntry)
            .where(AuditLogEntry.action == action)
            .order_by(AuditLogEntry.created_at)
        )
        return list(result.scalars().all())


async def jobs_of(db_session_factory: Factory, machine_id: uuid.UUID) -> list[DockerJob]:
    async with db_session_factory() as session:
        result = await session.execute(
            select(DockerJob)
            .where(DockerJob.machine_id == machine_id)
            .order_by(DockerJob.created_at)
        )
        return list(result.scalars().all())


async def get_row[T](db_session_factory: Factory, model: type[T], row_id: uuid.UUID) -> T | None:
    async with db_session_factory() as session:
        return await session.get(model, row_id)


async def follow(client: AsyncClient, location: str) -> str:
    """The page a redirect lands on, to read its signed flash message."""
    response = await client.get(location)
    assert response.status_code == 200, location
    return response.text
