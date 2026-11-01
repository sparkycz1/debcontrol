"""Taking what already runs on a machine under management, and drift of
managed stacks (`app.services.docker_adopt`, `app.services.docker_drift`):

- adopt a Compose project found on the machine as a stack
  (`action.terminal`: the stack's compose file and `.env` are stored);
- turn a `docker run` container into a new stack (`action.terminal`; the
  form is the new-stack form, filled in);
- check a stack for drift now (`action.updates`, like checking a stack
  before a deploy), and take the files changed on the machine over into
  a stack written in debcontrol (`action.terminal`).

Which files a project has is read from the machine, never taken from the
request, like everywhere on the Docker tab. Registered before
`machines_docker_stacks`, whose `projects/{project}/{action}` would
match `adopt`.
"""

from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import verify_csrf
from app.db.models.docker import StackSource
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_adopt, docker_drift, docker_jobs, docker_stacks
from app.services.docker_gate import GATES
from app.ssh.docker_cli import is_container_name_valid, is_project_name_valid
from app.tasks import docker_extras
from app.web.messages import LocalizedText
from app.web.routes.machines_common import _get_machine_or_404, machines_router, need_updates
from app.web.routes.machines_docker_common import (
    actor,
    docker_base,
    need_terminal,
    redirect,
    render,
    wait_task,
)
from app.web.routes.machines_docker_stacks import (
    _audit,
    _projects,
    _settings_details,
    _stack_or_404,
    form_extras,
)

router = machines_router()


@router.post(
    "/{machine_id}/docker/projects/{project}/adopt",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_project_adopt(
    request: Request,
    machine_id: uuid.UUID,
    project: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Make a stack written in debcontrol from a project found on the
    machine; nothing restarts until it is deployed."""
    if not is_project_name_valid(project):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such project.")
    machine = await _get_machine_or_404(machine_id, db, current_user)
    back = f"{docker_base(machine)}/stacks"
    if not machine.host_key_fingerprint:
        return redirect(back, error=LocalizedText(request, "docker.no_host_key"))
    managed = await docker_stacks.name_taken(db, machine.id, project)
    try:
        await docker_jobs.check_project(db, machine, project)
        protected = False
    except docker_jobs.ProtectedError:
        protected = True
    projects, error = await _projects(request, db, machine)
    if error is not None:
        return redirect(back, error=error)
    found = next((p for p in projects if p["name"] == project), None)
    if found is None or not found["config_files"] or not found["working_dir"]:
        return redirect(back, error=LocalizedText(request, "docker.stack.files_unknown"))
    working_dir = str(found["working_dir"]).rstrip("/")
    files = [str(f) for f in found["config_files"]]
    errors = docker_adopt.precheck_errors(
        project, working_dir, managed=managed, protected=protected
    )
    if not errors and await docker_stacks.directory_taken(db, machine.id, working_dir):
        errors = ["docker.stack.error.directory_taken"]
    read: dict[str, object] = {}
    app_settings = await get_or_create_app_settings(db)
    if not errors:
        result, error = await wait_task(
            request,
            docker_extras.docker_project_read.delay(str(machine.id), project, working_dir, files),
            app_settings.ssh_connect_timeout + 150,
        )
        if error is not None or result is None:
            return redirect(back, error=error or LocalizedText(request, "docker.adopt.error.read"))
        read = dict(result.get("read") or {})
        errors = docker_adopt.read_errors(read)
    if errors:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.project.adopt",
            f'Could not adopt Compose project "{project}" on "{machine.name}" ({errors[0]})',
            ok=False,
            denied=protected,
            details={"project": project, "reason": errors[0]},
        )
        details = str(read.get("config_error") or "")
        message = LocalizedText(request, errors[0], directory=working_dir, details=details)
        return redirect(back, error=message)
    result, error = await wait_task(
        request,
        docker_extras.docker_mark_stack_dir.delay(str(machine.id), project, working_dir),
        app_settings.ssh_connect_timeout + 60,
    )
    if error is not None:
        return redirect(back, error=error)
    stack = docker_adopt.new_stack(machine.id, project, working_dir, read, actor(current_user))
    db.add(stack)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.project.adopt",
        f'Adopted Compose project "{project}" on "{machine.name}" as a managed stack',
        details={**_settings_details(stack), "directory": working_dir, "files": files},
    )
    return redirect(
        f"{docker_base(machine)}/stacks/{stack.id}",
        notice=LocalizedText(request, "docker.adopt.done"),
    )


@router.get("/{machine_id}/docker/containers/{name}/to-stack", dependencies=[need_terminal])
async def docker_container_to_stack(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The new-stack form filled in from a `docker run` container; the
    stack takes the container over on its first deploy."""
    if not is_container_name_valid(name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such container.")
    machine = await _get_machine_or_404(machine_id, db, current_user)
    back = f"{docker_base(machine)}/containers/{name}"
    try:
        await docker_jobs.check_container(db, machine, name)
    except docker_jobs.ProtectedError:
        return redirect(back, error=LocalizedText(request, "docker.protected"))
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(
        request,
        docker_extras.docker_container_compose.delay(str(machine.id), name),
        app_settings.ssh_connect_timeout + 90,
    )
    if error is not None or result is None:
        return redirect(back, error=error or LocalizedText(request, "docker.convert.error.read"))
    form = docker_stacks.StackForm(
        name=str(result.get("service") or ""),
        source=StackSource.EDITOR,
        compose=str(result.get("compose") or ""),
        env=str(result.get("env") or ""),
        directory="",
    )
    return render(
        request,
        "machines/docker/stack_form.html",
        machine,
        current_user,
        "stacks",
        {
            "stack": None,
            "form": form,
            "errors": [],
            "replace_container": name,
            "convert_warnings": list(result.get("warnings") or []),
            "gates": GATES,
            **(await form_extras(db, machine, None)),
        },
    )


@router.post(
    "/{machine_id}/docker/stacks/{stack_id}/drift",
    dependencies=[need_updates, Depends(verify_csrf)],
)
async def docker_stack_drift(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Check the stack for drift now (reads only)."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    stack = await _stack_or_404(db, machine, stack_id)
    back = f"{docker_base(machine)}/stacks/{stack.id}"
    if not docker_drift.is_checkable(stack):
        return redirect(back, error=LocalizedText(request, "docker.drift.not_deployed"))
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(
        request,
        docker_extras.check_stack_drift.delay(str(stack.id)),
        app_settings.ssh_connect_timeout + 150,
    )
    if error is not None or result is None:
        return redirect(back, error=error)
    key = "docker.drift.found" if result.get("status") == "drift" else "docker.drift.none"
    if result.get("status") == "error":
        key = "docker.drift.error"
    return redirect(back, notice=LocalizedText(request, key))


@router.post(
    "/{machine_id}/docker/stacks/{stack_id}/import",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_stack_import(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Store the stack's `compose.yaml` and `.env` as they are on the
    machine now (changes made there are kept, not overwritten by the next
    deploy). Shared variables debcontrol appended stay shared."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    stack = await _stack_or_404(db, machine, stack_id)
    back = f"{docker_base(machine)}/stacks/{stack.id}"
    if stack.source != StackSource.EDITOR:
        return redirect(back, error=LocalizedText(request, "docker.drift.import_git"))
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(
        request,
        docker_extras.docker_stack_files_read.delay(str(stack.id)),
        app_settings.ssh_connect_timeout + 90,
    )
    if error is not None or result is None:
        return redirect(back, error=error)
    read = dict(result.get("read") or {})
    compose = read.get("compose")
    env = read.get("env")
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
        return redirect(back, error=LocalizedText(request, "docker.drift.import_invalid"))
    form.apply(stack)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.import",
        f'Took over the files of Docker stack "{stack.name}" from "{machine.name}"',
        details={"stack": stack.name},
    )
    return redirect(back, notice=LocalizedText(request, "docker.drift.imported"))
