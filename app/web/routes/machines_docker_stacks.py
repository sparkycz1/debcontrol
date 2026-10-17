"""Compose stacks on the Docker tab: the stacks debcontrol deploys itself
(`DockerStack` — written here, or taken from a Git repository) and every
other Compose project found on the machine.

What a project's files are is always read from the machine
(`docker compose ls` and its containers' labels), never taken from the
request: `up` with a file of one's choosing would start any container
with any mount, which is more than `action.updates` grants.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Depends, Form, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import DockerStack, StackSource
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_actions, docker_jobs, docker_stacks
from app.ssh.docker_cli import DockerCommandError, is_project_name_valid
from app.ssh.docker_compose import STACK_ACTIONS
from app.tasks import docker_jobs as docker_tasks
from app.web.messages import LocalizedText
from app.web.routes.machines_common import (
    _get_machine_or_404,
    machines_router,
    need_updates,
)
from app.web.routes.machines_docker_common import (
    actor,
    docker_base,
    need_terminal,
    redirect,
    render,
    render_partial,
    wait_task,
)

router = machines_router()

# Who may do which action on a project.
_ACTION_PERMISSION = {
    "start": Permission.ACTION_POWER,
    "stop": Permission.ACTION_POWER,
    "restart": Permission.ACTION_POWER,
    "down": Permission.ACTION_POWER,
    "up": Permission.ACTION_UPDATES,
    "update": Permission.ACTION_UPDATES,
}


async def _audit(
    db: AsyncSession,
    request: Request,
    machine: Machine,
    action: str,
    summary: str,
    *,
    ok: bool = True,
    details: dict[str, Any] | None = None,
) -> None:
    await log_event(
        db,
        request=request,
        action=action,
        summary=summary,
        outcome=AuditOutcome.SUCCESS if ok else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details=details,
    )


async def _stack_or_404(db: AsyncSession, machine: Machine, stack_id: uuid.UUID) -> DockerStack:
    stack = await docker_stacks.get_stack(db, machine.id, stack_id)
    if stack is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stack not found.")
    return stack


def _webhook_url(request: Request, token: str) -> str:
    return str(request.base_url).rstrip("/") + docker_stacks.WEBHOOK_PREFIX + token


@router.get("/{machine_id}/docker/stacks")
async def docker_stacks_page(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    stacks = await docker_stacks.list_stacks(db, machine.id)
    return render(
        request,
        "machines/docker/stacks.html",
        machine,
        current_user,
        "stacks",
        {
            "stacks": stacks,
            "changed": {s.id: docker_stacks.is_changed(s) for s in stacks},
            "protected_project": await docker_jobs.protected_project(db, machine),
        },
    )


async def _projects(
    request: Request, db: AsyncSession, machine: Machine
) -> tuple[list[dict[str, Any]], str | None]:
    """Every Compose project on the machine, with its containers and the
    directory and files it was started from."""
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(
        request,
        docker_tasks.docker_inventory.delay(str(machine.id), ["compose", "inspect"]),
        app_settings.ssh_connect_timeout + 90,
    )
    if error is not None or result is None:
        return [], error
    inventory = result.get("inventory") or {}
    projects: dict[str, dict[str, Any]] = {}
    for row in inventory.get("compose") or []:
        projects[row["name"]] = {
            "name": row["name"],
            "status": row.get("status") or "",
            "config_files": list(row.get("config_files") or []),
            "working_dir": "",
            "containers": [],
        }
    for container in inventory.get("containers") or []:
        name = container.get("compose_project")
        if not name:
            continue
        project = projects.setdefault(
            name,
            {"name": name, "status": "", "config_files": [], "working_dir": "", "containers": []},
        )
        project["containers"].append(container)
        if not project["working_dir"]:
            project["working_dir"] = container.get("compose_working_dir") or ""
        if not project["config_files"]:
            project["config_files"] = list(container.get("compose_config_files") or [])
    return sorted(projects.values(), key=lambda p: p["name"]), None


@router.get("/{machine_id}/docker/stacks/panel")
async def docker_stacks_panel(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    projects, error = await _projects(request, db, machine)
    managed = {s.name: s for s in await docker_stacks.list_stacks(db, machine.id)}
    return render_partial(
        request,
        "machines/docker/_projects_panel.html",
        {
            "machine": machine,
            "docker_base": docker_base(machine),
            "projects": projects,
            "managed": managed,
            "error": error,
            "protected_project": await docker_jobs.protected_project(db, machine),
            "can_power": current_user.has_permission(Permission.ACTION_POWER),
            "can_updates": current_user.has_permission(Permission.ACTION_UPDATES),
            "can_terminal": current_user.has_permission(Permission.ACTION_TERMINAL),
            "csrf_token": request.state.csrf_token,
        },
    )


def _form_from_request(form: Any) -> docker_stacks.StackForm:
    # "keep" the stored token, "set" a new one, or "remove" it.
    choice = str(form.get("git_token_action") or "keep")
    token: str | None = None
    if choice == "set":
        token = str(form.get("git_token") or "")
    elif choice == "remove":
        token = ""
    env_action = str(form.get("env_action") or "set")
    return docker_stacks.StackForm(
        name=str(form.get("name") or ""),
        source=str(form.get("source") or StackSource.EDITOR),
        compose=str(form.get("compose") or "").replace("\r\n", "\n"),
        env=str(form.get("env") or "").replace("\r\n", "\n") if env_action == "set" else None,
        git_url=str(form.get("git_url") or ""),
        git_branch=str(form.get("git_branch") or docker_stacks.DEFAULT_BRANCH),
        git_compose_path=str(form.get("git_compose_path") or docker_stacks.DEFAULT_COMPOSE_PATH),
        git_token=token,
        auto_sync=form.get("auto_sync") == "1",
    )


@router.get("/{machine_id}/docker/stacks/new", dependencies=[need_terminal])
async def docker_stack_new(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    return render(
        request,
        "machines/docker/stack_form.html",
        machine,
        current_user,
        "stacks",
        {"stack": None, "form": None, "errors": []},
    )


@router.post("/{machine_id}/docker/stacks", dependencies=[need_terminal, Depends(verify_csrf)])
async def docker_stack_create(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    raw = await request.form()
    form = _form_from_request(raw)
    errors = form.validate()
    if not errors and await docker_stacks.name_taken(db, machine.id, form.name):
        errors.append("docker.stack.error.name_taken")
    if not errors:
        try:
            await docker_jobs.check_project(db, machine, form.name)
        except docker_jobs.ProtectedError:
            errors.append("docker.stack.error.protected")
    if errors:
        return render(
            request,
            "machines/docker/stack_form.html",
            machine,
            current_user,
            "stacks",
            {"stack": None, "form": form, "errors": errors},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    stack = DockerStack(machine_id=machine.id, created_by=actor(current_user))
    form.apply(stack)
    db.add(stack)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.create",
        f'Created Docker stack "{stack.name}" on "{machine.name}"',
        details={"stack": stack.name, "source": stack.source, "git_url": stack.git_url},
    )
    if raw.get("deploy") == "1" and current_user.has_permission(Permission.ACTION_UPDATES):
        return await _deploy(request, db, machine, current_user, stack, pull=True)
    return redirect(f"{docker_base(machine)}/stacks/{stack.id}")


@router.get("/{machine_id}/docker/stacks/{stack_id}")
async def docker_stack_page(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    stack = await _stack_or_404(db, machine, stack_id)
    return await _stack_page(request, db, machine, current_user, stack)


async def _stack_page(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    user: User,
    stack: DockerStack,
    *,
    form: docker_stacks.StackForm | None = None,
    errors: list[str] | None = None,
    webhook_url: str | None = None,
    status_code: int = 200,
) -> Response:
    can_terminal = user.has_permission(Permission.ACTION_TERMINAL)
    return render(
        request,
        "machines/docker/stack_form.html",
        machine,
        user,
        "stacks",
        {
            "stack": stack,
            "form": form,
            "errors": errors or [],
            # The compose file and .env are for those who may edit them.
            "env_text": docker_stacks.env_text(stack) if can_terminal else "",
            "jobs": await docker_jobs.list_jobs(db, machine.id, limit=20, ref_id=stack.id),
            "changed": docker_stacks.is_changed(stack),
            "webhook_url": webhook_url,
        },
        status_code=status_code,
    )


@router.post(
    "/{machine_id}/docker/stacks/{stack_id}", dependencies=[need_terminal, Depends(verify_csrf)]
)
async def docker_stack_save(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    stack = await _stack_or_404(db, machine, stack_id)
    raw = await request.form()
    form = _form_from_request(raw)
    # A deployed stack keeps its name: it is the Compose project's name.
    form.name = stack.name
    errors = form.validate()
    if errors:
        return await _stack_page(
            request,
            db,
            machine,
            current_user,
            stack,
            form=form,
            errors=errors,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    form.apply(stack)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.edit",
        f'Edited Docker stack "{stack.name}" on "{machine.name}"',
        details={"stack": stack.name, "source": stack.source, "git_url": stack.git_url},
    )
    if raw.get("deploy") == "1" and current_user.has_permission(Permission.ACTION_UPDATES):
        return await _deploy(request, db, machine, current_user, stack, pull=True)
    return redirect(
        f"{docker_base(machine)}/stacks/{stack.id}",
        notice=LocalizedText(request, "docker.stack.saved"),
    )


async def _deploy(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    user: User,
    stack: DockerStack,
    *,
    pull: bool,
) -> Response:
    back = f"{docker_base(machine)}/stacks/{stack.id}"
    try:
        job = await docker_actions.deploy_stack(
            db, machine, stack, started_by=actor(user), pull=pull
        )
    except docker_jobs.ProtectedError:
        return redirect(back, error=LocalizedText(request, "docker.protected"))
    if job is None:
        return redirect(back, error=LocalizedText(request, "docker.job.already_queued"))
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.deploy",
        f'Started deploying Docker stack "{stack.name}" on "{machine.name}"',
        details={"stack": stack.name, "pull": pull},
    )
    return redirect(f"{docker_base(machine)}/jobs/{job.id}")


@router.post(
    "/{machine_id}/docker/stacks/{stack_id}/deploy",
    dependencies=[need_updates, Depends(verify_csrf)],
)
async def docker_stack_deploy(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    pull: str = Form("1"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    stack = await _stack_or_404(db, machine, stack_id)
    return await _deploy(request, db, machine, current_user, stack, pull=pull == "1")


@router.post(
    "/{machine_id}/docker/stacks/{stack_id}/sync",
    dependencies=[need_updates, Depends(verify_csrf)],
)
async def docker_stack_sync(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Check Git now": deploy when the branch has a new commit."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    stack = await _stack_or_404(db, machine, stack_id)
    back = f"{docker_base(machine)}/stacks/{stack.id}"
    if stack.source != StackSource.GIT:
        return redirect(back)
    try:
        await docker_jobs.check_project(db, machine, stack.name)
    except docker_jobs.ProtectedError:
        return redirect(back, error=LocalizedText(request, "docker.protected"))
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(
        request,
        docker_tasks.sync_git_stack.delay(str(stack.id), actor(current_user)),
        app_settings.ssh_connect_timeout + 150,
    )
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.sync",
        f'Checked Git for Docker stack "{stack.name}" on "{machine.name}"',
        ok=error is None,
        details={"stack": stack.name, "error": error} if error else {"stack": stack.name},
    )
    if error is not None:
        return redirect(back, error=error)
    if result and result.get("deployed"):
        return redirect(back, notice=LocalizedText(request, "docker.stack.sync_deploying"))
    return redirect(back, notice=LocalizedText(request, "docker.stack.sync_up_to_date"))


@router.post(
    "/{machine_id}/docker/stacks/{stack_id}/webhook",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_stack_webhook(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    remove: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Make a new webhook URL (shown once, on this response only — never
    put in a redirect URL) or remove it."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    stack = await _stack_or_404(db, machine, stack_id)
    if stack.source != StackSource.GIT:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Not a Git stack.")
    url: str | None = None
    if remove == "1":
        stack.webhook_token_hash = None
    else:
        token, digest = docker_stacks.new_webhook_token()
        stack.webhook_token_hash = digest
        url = _webhook_url(request, token)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.webhook",
        f'{"Removed" if url is None else "Created a new"} webhook of Docker stack '
        f'"{stack.name}" on "{machine.name}"',
        details={"stack": stack.name, "removed": url is None},
    )
    return await _stack_page(request, db, machine, current_user, stack, webhook_url=url)


@router.post(
    "/{machine_id}/docker/stacks/{stack_id}/delete",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_stack_delete(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    remove_volumes: str = Form(""),
    confirm_name: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Take the stack down, delete its files on the machine, and forget it.
    Its named volumes go too only when asked, with its name typed."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    stack = await _stack_or_404(db, machine, stack_id)
    back = f"{docker_base(machine)}/stacks/{stack.id}"
    volumes = remove_volumes == "1"
    if volumes and confirm_name.strip() != stack.name:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.stack.delete",
            f'Refused to delete Docker stack "{stack.name}" with its volumes: name not confirmed',
            ok=False,
            details={"stack": stack.name},
        )
        return redirect(back, error=LocalizedText(request, "docker.stack.confirm_mismatch"))
    if stack.deployed_at is None and stack.last_status is None:
        name = stack.name
        await db.delete(stack)
        await db.commit()
        await _audit(
            db,
            request,
            machine,
            "machine.docker.stack.delete",
            f'Deleted Docker stack "{name}" (never deployed) on "{machine.name}"',
            details={"stack": name},
        )
        return redirect(f"{docker_base(machine)}/stacks")
    try:
        job = await docker_actions.stack_action(
            db,
            machine,
            stack.name,
            "remove",
            started_by=actor(current_user),
            stack=stack,
            remove_volumes=volumes,
        )
    except docker_jobs.ProtectedError:
        return redirect(back, error=LocalizedText(request, "docker.protected"))
    if job is None:
        return redirect(back, error=LocalizedText(request, "docker.job.already_queued"))
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.delete",
        f'Started deleting Docker stack "{stack.name}" on "{machine.name}"'
        + (" with its volumes" if volumes else ""),
        details={"stack": stack.name, "volumes": volumes},
    )
    return redirect(f"{docker_base(machine)}/jobs/{job.id}")


@router.post(
    "/{machine_id}/docker/projects/{project}/{action}", dependencies=[Depends(verify_csrf)]
)
async def docker_project_action(
    request: Request,
    machine_id: uuid.UUID,
    project: str,
    action: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """start / stop / restart / down (`action.power`), up / pull & recreate
    (`action.updates`) of any Compose project on the machine."""
    if action not in STACK_ACTIONS or not is_project_name_valid(project):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")
    if not current_user.has_permission(_ACTION_PERMISSION[action]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    machine = await _get_machine_or_404(machine_id, db, current_user)
    back = f"{docker_base(machine)}/stacks"
    managed = next(
        (s for s in await docker_stacks.list_stacks(db, machine.id) if s.name == project), None
    )
    working_dir = ""
    files: list[str] = []
    if action in ("up", "update") and managed is None:
        projects, error = await _projects(request, db, machine)
        found = next((p for p in projects if p["name"] == project), None)
        if error is not None or found is None or not found["config_files"]:
            return redirect(
                back, error=error or LocalizedText(request, "docker.stack.files_unknown")
            )
        working_dir = str(found["working_dir"] or "")
        files = [str(f) for f in found["config_files"]]
    try:
        job = await docker_actions.stack_action(
            db,
            machine,
            project,
            action,
            started_by=actor(current_user),
            working_dir=working_dir,
            files=files,
            stack=managed,
        )
    except docker_jobs.ProtectedError:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.stack.action",
            f'Refused "{action}" of Compose project "{project}" on "{machine.name}": '
            "debcontrol runs in it",
            ok=False,
            details={"project": project, "action": action},
        )
        return redirect(back, error=LocalizedText(request, "docker.protected"))
    except DockerCommandError as exc:
        return redirect(back, error=str(exc))
    if job is None:
        return redirect(back, error=LocalizedText(request, "docker.job.already_queued"))
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.action",
        f'Started "{action}" of Compose project "{project}" on "{machine.name}"',
        details={"project": project, "action": action},
    )
    return redirect(f"{docker_base(machine)}/jobs/{job.id}")


@router.get("/{machine_id}/docker/projects/{project}/compose", dependencies=[need_terminal])
async def docker_project_compose(
    request: Request,
    machine_id: uuid.UUID,
    project: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The compose file(s) a project found on the machine was started from."""
    if not is_project_name_valid(project):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such project.")
    machine = await _get_machine_or_404(machine_id, db, current_user)
    projects, error = await _projects(request, db, machine)
    found = next((p for p in projects if p["name"] == project), None)
    files: list[dict[str, Any]] = []
    if found is not None:
        app_settings = await get_or_create_app_settings(db)
        for path in found["config_files"][:10]:
            result, file_error = await wait_task(
                request,
                docker_tasks.docker_compose_file.delay(str(machine.id), str(path)),
                app_settings.ssh_connect_timeout + 90,
            )
            files.append(
                {
                    "path": path,
                    "content": (result or {}).get("content") if file_error is None else None,
                    "error": file_error,
                }
            )
    return render(
        request,
        "machines/docker/project_compose.html",
        machine,
        current_user,
        "stacks",
        {"project": project, "found": found, "files": files, "error": error},
    )
