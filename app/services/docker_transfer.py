"""Moving or cloning a stack debcontrol manages to another machine, with
its data (a stack's page -> *Move or clone*, `POST .../stacks/{id}/transfer`).

`start` checks what can be checked here, adds the stack to the target
machine (same compose file or Git source, `.env`, settings; no webhook,
no history, nothing deployed yet) and queues a `stack_transfer` job on
the target. The job (`app.tasks.docker_jobs._job_stack_transfer`) copies
the data through debcontrol (`app.ssh.docker_transfer`) and then queues
an ordinary deploy there:

- **clone**: the source is stopped only while its data is copied, then
  started again; both run afterwards (mind ports and host names);
- **move**: the source's containers are taken down (`docker compose
  down`, so a `restart: always` one doesn't come back with a reboot);
  its stack, volumes and files stay until someone deletes them, after
  checking the copy.

Without "copy data" only the stack itself is set up on the target.
Needs `action.terminal` and `action.updates` (it reads data and deploys)
and both machines visible to the account.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.docker import DockerJob, DockerJobKind, DockerJobStatus, DockerStack
from app.db.models.machine import Machine
from app.db.models.user import User
from app.services import docker_jobs
from app.services.access_scope import machines_visible_to
from app.services.docker_actions import queue_job

MODES = ("copy", "move")


class TransferError(Exception):
    """Refused before anything was done; `key` is an i18n key."""

    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


async def targets(db: AsyncSession, user: User, source: Machine) -> list[Machine]:
    """The machines a stack of `source` can go to: visible to `user`, with
    a confirmed host key and Docker reachable at the last sample."""
    query = (await machines_visible_to(db, user)).where(
        Machine.id != source.id,
        Machine.host_key_fingerprint.is_not(None),
        Machine.docker_status == "ok",
    )
    result = await db.execute(query.order_by(Machine.name))
    return list(result.scalars().all())


def _copy(stack: DockerStack, target: Machine, actor: str) -> DockerStack:
    return DockerStack(
        machine_id=target.id,
        name=stack.name,
        source=stack.source,
        directory=stack.directory,
        compose_content=stack.compose_content,
        env_encrypted=stack.env_encrypted,
        git_url=stack.git_url,
        git_branch=stack.git_branch,
        git_compose_path=stack.git_compose_path,
        git_token_encrypted=stack.git_token_encrypted,
        git_compose_overrides=list(stack.git_compose_overrides or []) or None,
        git_ssh_key_encrypted=stack.git_ssh_key_encrypted,
        git_ssh_public_key=stack.git_ssh_public_key,
        git_known_hosts=stack.git_known_hosts,
        auto_sync=stack.auto_sync,
        keep_history=stack.keep_history,
        auto_rollback=stack.auto_rollback,
        vulnerability_gate=stack.vulnerability_gate,
        shared_variables=list(stack.shared_variables or []) or None,
        drift_check=stack.drift_check,
        created_by=actor,
    )


async def start(
    db: AsyncSession,
    *,
    user: User,
    source: Machine,
    stack: DockerStack,
    target_id: object,
    mode: str,
    data: bool,
    actor: str,
) -> tuple[DockerJob, DockerStack]:
    """Add the stack to the target and queue the copy. Raises
    `TransferError` (nothing changed) or `docker_jobs.ProtectedError`."""
    if mode not in MODES:
        raise TransferError("docker.transfer.error.mode")
    target = next((m for m in await targets(db, user, source) if str(m.id) == str(target_id)), None)
    if target is None:
        raise TransferError("docker.transfer.error.target")
    await docker_jobs.check_project(db, source, stack.name)
    await docker_jobs.check_project(db, target, stack.name)
    existing = await db.scalar(
        select(DockerStack.id).where(
            DockerStack.machine_id == target.id, DockerStack.name == stack.name
        )
    )
    if existing is not None:
        raise TransferError("docker.transfer.error.exists")
    busy = await db.scalar(
        select(DockerJob.id).where(
            DockerJob.machine_id == source.id,
            DockerJob.ref_id == stack.id,
            DockerJob.status.in_((DockerJobStatus.PENDING, DockerJobStatus.RUNNING)),
        )
    )
    if busy is not None:
        raise TransferError("docker.transfer.error.busy")
    copy = _copy(stack, target, actor)
    db.add(copy)
    await db.flush()
    job = await queue_job(
        db,
        target,
        DockerJobKind.STACK_TRANSFER,
        stack.name,
        started_by=actor,
        params={
            "source_machine_id": str(source.id),
            "source_stack_id": str(stack.id),
            "mode": mode,
            "data": data,
        },
        ref_id=copy.id,
    )
    if job is None:
        await db.rollback()
        raise TransferError("docker.transfer.error.busy")
    return job, copy
