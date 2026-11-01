"""REST API for taking what runs on a machine under management, and for
drift of managed stacks — the same as the web routes in
`app.web.routes.machines_docker_adopt`, with the same permissions:

- `POST .../docker/projects/{project}/adopt` (`action.terminal`);
- `GET .../docker/containers/{name}/compose` (`action.terminal`): a
  `docker run` container as a compose file and `.env`, to create a stack
  with `replace_container` set (`POST .../docker/stacks`);
- `POST .../docker/stacks/{stack_id}/drift` (`action.updates`);
- `POST .../docker/stacks/{stack_id}/import` (`action.terminal`).

Registered before `api_v1_docker`, whose `projects/{project}/{action}`
would match `adopt`.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.docker import StackSource
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_adopt, docker_drift, docker_jobs, docker_stacks, docker_variables
from app.ssh.docker_cli import is_container_name_valid, is_project_name_valid
from app.tasks import docker_extras
from app.web.routes.api_v1_docker import (
    _audit,
    _bad,
    _projects,
    _protected,
    _ready,
    _settings_details,
    _stack,
    _stack_or_404,
    _wait,
)
from app.web.routes.machines_common import _get_machine_or_404

router = APIRouter(prefix="/api/v1/machines/{machine_id}/docker", tags=["docker"])
_updates = Depends(require_api_permission(Permission.ACTION_UPDATES))
_terminal = Depends(require_api_permission(Permission.ACTION_TERMINAL))


@router.post(
    "/projects/{project}/adopt", dependencies=[_terminal], status_code=status.HTTP_201_CREATED
)
async def docker_project_adopt_api(
    request: Request,
    machine_id: uuid.UUID,
    project: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Make a managed stack (written in debcontrol) from a Compose project
    found on the machine, keeping its name and directory. Nothing
    restarts until the stack is deployed. 422 with the reason (an i18n
    key) when it can't be adopted."""
    if not is_project_name_valid(project):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such project.")
    machine = await _get_machine_or_404(machine_id, db, user)
    _ready(machine)
    try:
        await docker_jobs.check_project(db, machine, project)
    except docker_jobs.ProtectedError as exc:
        raise _protected() from exc
    found = next((p for p in await _projects(request, db, machine) if p["name"] == project), None)
    if found is None or not found["config_files"] or not found["working_dir"]:
        raise _bad("This project's compose files aren't known.")
    working_dir = str(found["working_dir"]).rstrip("/")
    files = [str(f) for f in found["config_files"]]
    errors = docker_adopt.precheck_errors(
        project,
        working_dir,
        managed=await docker_stacks.name_taken(db, machine.id, project),
        protected=False,
    )
    if not errors and await docker_stacks.directory_taken(db, machine.id, working_dir):
        errors = ["docker.stack.error.directory_taken"]
    if errors:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors)
    result = await _wait(
        request,
        db,
        docker_extras.docker_project_read.delay(str(machine.id), project, working_dir, files),
        150,
    )
    read = dict(result.get("read") or {})
    if errors := docker_adopt.read_errors(read):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=[*errors, str(read.get("config_error") or "")] if read.get("config_error")
            else errors,
        )
    await _wait(
        request,
        db,
        docker_extras.docker_mark_stack_dir.delay(str(machine.id), project, working_dir),
        60,
    )
    stack = docker_adopt.new_stack(machine.id, project, working_dir, read, user.username)
    db.add(stack)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.project.adopt",
        f'Adopted Compose project "{project}" on "{machine.name}" as a managed stack',
        {**_settings_details(stack), "directory": working_dir, "files": files},
    )
    shared = await docker_variables.resolve(db, stack)
    return {"stack": _stack(stack, secrets=True, shared=shared)}


@router.get("/containers/{name}/compose", dependencies=[_terminal])
async def docker_container_compose_api(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """A container started with `docker run` as a compose file (`compose`)
    and `.env` (`env`), with `warnings` for what wasn't converted. Create
    the stack with these and `replace_container` = the container's name."""
    if not is_container_name_valid(name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such container.")
    machine = await _get_machine_or_404(machine_id, db, user)
    _ready(machine)
    try:
        await docker_jobs.check_container(db, machine, name)
    except docker_jobs.ProtectedError as exc:
        raise _protected() from exc
    result = await _wait(
        request, db, docker_extras.docker_container_compose.delay(str(machine.id), name), 90
    )
    return {
        "name": result.get("service"),
        "compose": result.get("compose"),
        "env": result.get("env"),
        "warnings": list(result.get("warnings") or []),
        "replace_container": name,
    }


@router.post("/stacks/{stack_id}/drift", dependencies=[_updates])
async def docker_stack_drift_api(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Check a stack for drift now (reads only): `status` ok / drift /
    error, with `details` and a `summary`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    _ready(machine)
    stack = await _stack_or_404(db, machine, stack_id)
    if not docker_drift.is_checkable(stack):
        raise _bad("The stack has not been deployed by debcontrol yet.")
    result = await _wait(request, db, docker_extras.check_stack_drift.delay(str(stack.id)), 150)
    details = dict(result.get("details") or {})
    return {
        "status": result.get("status"),
        "details": details,
        "summary": docker_drift.summary(details),
    }


@router.post("/stacks/{stack_id}/import", dependencies=[_terminal])
async def docker_stack_import_api(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Store a stack's `compose.yaml` and `.env` as they are on the
    machine now (a stack written in debcontrol only)."""
    machine = await _get_machine_or_404(machine_id, db, user)
    _ready(machine)
    stack = await _stack_or_404(db, machine, stack_id)
    if stack.source != StackSource.EDITOR:
        raise _bad("Only a stack written in debcontrol can take files over from the machine.")
    result = await _wait(
        request, db, docker_extras.docker_stack_files_read.delay(str(stack.id)), 90
    )
    read = dict(result.get("read") or {})
    compose, env = read.get("compose"), read.get("env")
    form = docker_stacks.StackForm(
        name=stack.name,
        source=StackSource.EDITOR,
        compose=compose.replace("\r\n", "\n") if isinstance(compose, str) else "",
        env=docker_adopt.strip_shared(env) if isinstance(env, str) else "",
        keep_history=stack.keep_history,
        auto_rollback=stack.auto_rollback,
        vulnerability_gate=stack.vulnerability_gate,
    )
    if not isinstance(compose, str) or form.validate(stack):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=["docker.drift.import_invalid"],
        )
    form.apply(stack)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.import",
        f'Took over the files of Docker stack "{stack.name}" from "{machine.name}"',
        {"stack": stack.name},
    )
    shared = await docker_variables.resolve(db, stack)
    return {"stack": _stack(stack, secrets=True, shared=shared)}
