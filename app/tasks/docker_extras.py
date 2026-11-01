"""Background work for private registries, adopting what runs on a
machine, and drift (`app.services.docker_registries`,
`app.services.docker_adopt`, `app.services.docker_drift`).

Each task is `async def _thing(...)` plus a one-line Celery wrapper, like
`app.tasks.docker_jobs`; the fan-outs queue one task per machine or stack
and never await them inline.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret
from app.db import session as db_session
from app.db.models.docker import DockerRegistryLogin, DockerStack
from app.db.models.machine import Machine
from app.db.models.notification_rule import NotificationEventType
from app.services import docker_drift, docker_registries
from app.services.notifications import notify
from app.ssh.docker_adopt import (
    build_mark_script,
    build_project_read_script,
    build_stack_files_read_script,
    parse_read_output,
)
from app.ssh.docker_cli import (
    DockerAccessError,
    DockerCommandError,
    run_script,
)
from app.ssh.docker_convert import build_inspect_script, parse_inspect_output, to_compose
from app.ssh.docker_drift import parse_drift_output
from app.ssh.docker_registry import build_login_command, build_logout_command, login_message
from app.ssh.exceptions import SSHConnectionError
from app.tasks.celery_app import celery_app
from app.tasks.docker_jobs import _READ_ERRORS, _error, _machine_and_secret

logger = logging.getLogger(__name__)

_SHORT_TASK_TIME_LIMIT = 300


# --- Registry logins ----------------------------------------------------------


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def reconcile_logins(
    session: AsyncSession,
    machine: Machine,
    secret: str | None,
    connect_timeout: int,
    *,
    force: bool = False,
) -> dict[str, int]:
    """Bring the machine's registry logins in line with what applies to it:
    log in where a login is missing, failed, came from another registry
    entry or predates a change of it (every one with `force`), and log out
    of servers no entry applies to any more. Commits."""
    wanted = await docker_registries.applicable(session, machine)
    rows = {
        row.server: row
        for row in (
            await session.execute(
                select(DockerRegistryLogin).where(DockerRegistryLogin.machine_id == machine.id)
            )
        ).scalars()
    }
    counts = {"logged_in": 0, "failed": 0, "logged_out": 0}
    for server, registry in wanted.items():
        row = rows.get(server)
        if not (
            force
            or row is None
            or row.status != "ok"
            or row.registry_id != registry.id
            or _aware(row.checked_at) < _aware(registry.updated_at)
        ):
            counts["logged_in"] += 1
            continue
        try:
            output = await run_script(
                machine,
                secret,
                connect_timeout,
                build_login_command(server, registry.username),
                stdin=decrypt_secret(registry.password_encrypted),
            )
            ok = output.exit_status == 0
            message = login_message(output.output) or ("Login Succeeded" if ok else "Failed.")
        except (DockerCommandError, DockerAccessError, SSHConnectionError, OSError) as exc:
            ok, message = False, str(exc)[:480] or type(exc).__name__
        if row is None:
            row = DockerRegistryLogin(machine_id=machine.id, server=server)
            session.add(row)
        row.registry_id = registry.id
        row.status = "ok" if ok else "failed"
        row.message = message[:500]
        row.checked_at = datetime.now(UTC)
        counts["logged_in" if ok else "failed"] += 1
    for server, row in rows.items():
        if server in wanted:
            continue
        if row.status == "ok":
            try:
                await run_script(machine, secret, connect_timeout, build_logout_command(server))
            except (DockerCommandError, DockerAccessError, SSHConnectionError, OSError):
                logger.info("docker logout %s failed on %s", server, machine.name)
        await session.delete(row)
        counts["logged_out"] += 1
    await session.commit()
    return counts


async def _sync_registry_logins(machine_id: str, force: bool = False) -> dict[str, Any]:
    async with db_session.AsyncSessionLocal() as session:
        try:
            machine, secret, timeout = await _machine_and_secret(session, machine_id)
        except _READ_ERRORS as exc:
            return _error(exc)
        counts = await reconcile_logins(session, machine, secret, timeout, force=force)
    return {"ok": True, **counts}


@celery_app.task(
    name="app.tasks.docker_extras.sync_registry_logins", time_limit=_SHORT_TASK_TIME_LIMIT
)
def sync_registry_logins(machine_id: str, force: bool = False) -> dict[str, Any]:
    return asyncio.run(_sync_registry_logins(machine_id, force))


def queue_registry_sync(machine_ids: list[uuid.UUID], *, force: bool = False) -> int:
    """One `sync_registry_logins` per machine, never awaited."""
    for machine_id in dict.fromkeys(machine_ids):
        sync_registry_logins.delay(str(machine_id), force)
    return len(set(machine_ids))


# --- Adopting -----------------------------------------------------------------


async def _docker_project_read(
    machine_id: str, project: str, working_dir: str, files: list[str]
) -> dict[str, Any]:
    """A project's compose file(s) and `.env`, and whether its directory
    is writable (`build_project_read_script`)."""
    async with db_session.AsyncSessionLocal() as session:
        try:
            machine, secret, timeout = await _machine_and_secret(session, machine_id)
            output = await run_script(
                machine,
                secret,
                timeout,
                build_project_read_script(project, working_dir, files),
                run_timeout_seconds=120,
            )
        except _READ_ERRORS as exc:
            return _error(exc)
    if output.exit_status != 0:
        return {"ok": False, "error": output.output.strip()[-300:] or "Could not read the project."}
    return {"ok": True, "read": parse_read_output(output.output)}


@celery_app.task(
    name="app.tasks.docker_extras.docker_project_read", time_limit=_SHORT_TASK_TIME_LIMIT
)
def docker_project_read(
    machine_id: str, project: str, working_dir: str, files: list[str]
) -> dict[str, Any]:
    return asyncio.run(_docker_project_read(machine_id, project, working_dir, files))


async def _docker_mark_stack_dir(machine_id: str, name: str, directory: str) -> dict[str, Any]:
    async with db_session.AsyncSessionLocal() as session:
        try:
            machine, secret, timeout = await _machine_and_secret(session, machine_id)
            output = await run_script(machine, secret, timeout, build_mark_script(name, directory))
        except _READ_ERRORS as exc:
            return _error(exc)
    if output.exit_status == 0 and "@@DC_DONE" in output.output:
        return {"ok": True}
    return {"ok": False, "error": output.output.strip()[-300:] or "Could not write the marker."}


@celery_app.task(
    name="app.tasks.docker_extras.docker_mark_stack_dir", time_limit=_SHORT_TASK_TIME_LIMIT
)
def docker_mark_stack_dir(machine_id: str, name: str, directory: str) -> dict[str, Any]:
    return asyncio.run(_docker_mark_stack_dir(machine_id, name, directory))


async def _docker_stack_files_read(stack_id: str) -> dict[str, Any]:
    """A managed stack's `compose.yaml` and `.env` as they are on the machine."""
    async with db_session.AsyncSessionLocal() as session:
        stack = await session.get(DockerStack, uuid.UUID(stack_id))
        if stack is None:
            return {"ok": False, "error": "Stack not found."}
        try:
            machine, secret, timeout = await _machine_and_secret(session, str(stack.machine_id))
            script = build_stack_files_read_script(stack.name, stack.directory or "")
            output = await run_script(machine, secret, timeout, script)
        except _READ_ERRORS as exc:
            return _error(exc)
    if output.exit_status != 0:
        return {"ok": False, "error": output.output.strip()[-300:] or "Could not read the files."}
    return {"ok": True, "read": parse_read_output(output.output)}


@celery_app.task(
    name="app.tasks.docker_extras.docker_stack_files_read", time_limit=_SHORT_TASK_TIME_LIMIT
)
def docker_stack_files_read(stack_id: str) -> dict[str, Any]:
    return asyncio.run(_docker_stack_files_read(stack_id))


async def _docker_container_compose(machine_id: str, container: str) -> dict[str, Any]:
    """A `docker run` container as a compose file and `.env`
    (`app.ssh.docker_convert`)."""
    async with db_session.AsyncSessionLocal() as session:
        try:
            machine, secret, timeout = await _machine_and_secret(session, machine_id)
            output = await run_script(machine, secret, timeout, build_inspect_script(container))
            if output.exit_status != 0:
                return {
                    "ok": False,
                    "error": output.output.strip()[-300:] or "The container could not be read.",
                }
            data, image = parse_inspect_output(output.output)
            labels = dict((data.get("Config") or {}).get("Labels") or {})
            if labels.get("com.docker.compose.project"):
                return {"ok": False, "error": "This container belongs to a Compose project."}
            converted = to_compose(data, image)
        except _READ_ERRORS as exc:
            return _error(exc)
    return {
        "ok": True,
        "service": converted.service,
        "compose": converted.compose,
        "env": converted.env,
        "warnings": converted.warnings,
    }


@celery_app.task(
    name="app.tasks.docker_extras.docker_container_compose", time_limit=_SHORT_TASK_TIME_LIMIT
)
def docker_container_compose(machine_id: str, container: str) -> dict[str, Any]:
    return asyncio.run(_docker_container_compose(machine_id, container))


# --- Drift --------------------------------------------------------------------


async def _check_stack_drift(stack_id: str) -> dict[str, Any]:
    """Compare a stack on its machine with what debcontrol deployed, store
    the result, and notify when it just turned to drift."""
    async with db_session.AsyncSessionLocal() as session:
        stack = await session.get(DockerStack, uuid.UUID(stack_id))
        if stack is None:
            return {"ok": False, "error": "Stack not found."}
        if not docker_drift.is_checkable(stack):
            return {"ok": False, "error": "The stack has not been deployed by debcontrol yet."}
        try:
            machine, secret, timeout = await _machine_and_secret(session, str(stack.machine_id))
            output = await run_script(
                machine, secret, timeout, docker_drift.script(stack), run_timeout_seconds=120
            )
        except _READ_ERRORS as exc:
            result = _error(exc)
            docker_drift.store(stack, "error", {"message": str(result.get("error") or "")})
            await session.commit()
            return result
        status, details = docker_drift.evaluate(stack, parse_drift_output(output.output))
        turned = docker_drift.store(stack, status, details)
        await session.commit()
        if turned:
            await notify(
                session,
                NotificationEventType.DOCKER_STACK_DRIFT,
                machine=machine,
                context={"stack": stack.name, "details": docker_drift.summary(details)},
            )
    return {"ok": True, "status": status, "details": details}


@celery_app.task(
    name="app.tasks.docker_extras.check_stack_drift", time_limit=_SHORT_TASK_TIME_LIMIT
)
def check_stack_drift(stack_id: str) -> dict[str, Any]:
    return asyncio.run(_check_stack_drift(stack_id))


async def _check_all_stack_drift() -> int:
    """Hourly: one `check_stack_drift` per deployed stack with the check
    switched on, on an active machine."""
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(
            select(DockerStack.id)
            .join(Machine, Machine.id == DockerStack.machine_id)
            .where(
                DockerStack.drift_check.is_(True),
                DockerStack.deployed_hash.is_not(None),
                Machine.is_active,
                Machine.host_key_fingerprint.is_not(None),
            )
        )
        ids = [row[0] for row in result.all()]
    for stack_id in ids:
        check_stack_drift.delay(str(stack_id))
    return len(ids)


@celery_app.task(name="app.tasks.docker_extras.check_all_stack_drift")
def check_all_stack_drift() -> int:
    return asyncio.run(_check_all_stack_drift())
