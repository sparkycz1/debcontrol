"""restic backups on the Docker tab (`DockerBackup`): the list, their
settings and snapshots, and running, checking, pruning and restoring.

Settings and restores need `action.terminal` (they choose what is read
from and written to the machine, and hold the repository's secrets);
running, checking and pruning a configured backup need `action.updates`.
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
from app.db.models.docker import DockerBackup
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_actions, docker_backups, docker_jobs
from app.ssh.docker_cli import DockerCommandError
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


async def _audit(
    db: AsyncSession,
    request: Request,
    machine: Machine,
    action: str,
    summary: str,
    *,
    ok: bool = True,
    denied: bool = False,
    details: dict[str, Any] | None = None,
) -> None:
    await log_event(
        db,
        request=request,
        action=action,
        summary=summary,
        # A safeguard that blocked the request (typed confirmation, debcontrol's
        # own) is DENIED, like elsewhere in the app; a failed attempt is FAILURE.
        outcome=(
            AuditOutcome.DENIED
            if denied
            else AuditOutcome.SUCCESS
            if ok
            else AuditOutcome.FAILURE
        ),
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details=details,
    )


async def _backup_or_404(
    db: AsyncSession, machine: Machine, backup_id: uuid.UUID
) -> DockerBackup:
    backup = await docker_backups.get_backup(db, machine.id, backup_id)
    if backup is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Backup not found.")
    return backup


def _form(raw: Any) -> docker_backups.BackupForm:
    return docker_backups.BackupForm(
        name=str(raw.get("name") or ""),
        repository=str(raw.get("repository") or ""),
        password=str(raw.get("password") or ""),
        env=str(raw.get("env") or "").replace("\r\n", "\n"),
        volumes=str(raw.get("volumes") or ""),
        paths=str(raw.get("paths") or ""),
        excludes=str(raw.get("excludes") or ""),
        stop_containers=raw.get("stop_containers") == "1",
        enabled=raw.get("enabled") == "1",
        keep_last=str(raw.get("keep_last") or ""),
        keep_daily=str(raw.get("keep_daily") or ""),
        keep_weekly=str(raw.get("keep_weekly") or ""),
        keep_monthly=str(raw.get("keep_monthly") or ""),
        clear_env=raw.get("clear_env") == "1",
    )


@router.get("/{machine_id}/docker/backups")
async def docker_backups_page(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    return render(
        request,
        "machines/docker/backups.html",
        machine,
        current_user,
        "backups",
        {"backups": await docker_backups.list_backups(db, machine.id)},
    )


@router.get("/{machine_id}/docker/backups/new", dependencies=[need_terminal])
async def docker_backup_new(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    return render(
        request,
        "machines/docker/backup_form.html",
        machine,
        current_user,
        "backups",
        {"backup": None, "form": None, "errors": []},
    )


@router.post("/{machine_id}/docker/backups", dependencies=[need_terminal, Depends(verify_csrf)])
async def docker_backup_create(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    form = _form(await request.form())
    errors = form.validate(existing=None)
    if not errors and await docker_backups.name_taken(db, machine.id, form.name):
        errors.append("docker.backup.error.name_taken")
    if errors:
        return render(
            request,
            "machines/docker/backup_form.html",
            machine,
            current_user,
            "backups",
            {"backup": None, "form": form, "errors": errors},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    backup = DockerBackup(machine_id=machine.id, created_by=actor(current_user))
    form.apply(backup)
    db.add(backup)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.backup.create",
        f'Created Docker backup "{backup.name}" on "{machine.name}"',
        details={
            "backup": backup.name,
            "repository": backup.repository_display,
            "volumes": backup.volumes,
            "paths": backup.paths,
        },
    )
    return redirect(f"{docker_base(machine)}/backups/{backup.id}")


@router.get("/{machine_id}/docker/backups/{backup_id}")
async def docker_backup_page(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    backup = await _backup_or_404(db, machine, backup_id)
    return await _backup_page(request, db, machine, current_user, backup)


async def _backup_page(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    user: User,
    backup: DockerBackup,
    *,
    form: docker_backups.BackupForm | None = None,
    errors: list[str] | None = None,
    status_code: int = 200,
) -> Response:
    return render(
        request,
        "machines/docker/backup_form.html",
        machine,
        user,
        "backups",
        {
            "backup": backup,
            "form": form,
            "errors": errors or [],
            "jobs": await docker_jobs.list_jobs(db, machine.id, limit=20, ref_id=backup.id),
            "has_retention": docker_backups.has_retention(backup),
        },
        status_code=status_code,
    )


@router.post(
    "/{machine_id}/docker/backups/{backup_id}", dependencies=[need_terminal, Depends(verify_csrf)]
)
async def docker_backup_save(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    backup = await _backup_or_404(db, machine, backup_id)
    form = _form(await request.form())
    errors = form.validate(existing=backup)
    if not errors and await docker_backups.name_taken(
        db, machine.id, form.name, exclude=backup.id
    ):
        errors.append("docker.backup.error.name_taken")
    if errors:
        return await _backup_page(
            request,
            db,
            machine,
            current_user,
            backup,
            form=form,
            errors=errors,
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    form.apply(backup)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.backup.edit",
        f'Edited Docker backup "{backup.name}" on "{machine.name}"',
        details={
            "backup": backup.name,
            "repository": backup.repository_display,
            "volumes": backup.volumes,
            "paths": backup.paths,
        },
    )
    return redirect(
        f"{docker_base(machine)}/backups/{backup.id}",
        notice=LocalizedText(request, "docker.backup.saved"),
    )


@router.post(
    "/{machine_id}/docker/backups/{backup_id}/delete",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_backup_delete(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Forget the backup in debcontrol. The repository and its snapshots
    are left as they are."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    backup = await _backup_or_404(db, machine, backup_id)
    name = backup.name
    await db.delete(backup)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.backup.delete",
        f'Deleted Docker backup "{name}" on "{machine.name}"',
        details={"backup": name},
    )
    return redirect(f"{docker_base(machine)}/backups")


@router.post(
    "/{machine_id}/docker/backups/{backup_id}/restore",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_backup_restore(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Restore a snapshot onto the backup's volumes and paths. The machine's
    name has to be typed: it overwrites live data."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    backup = await _backup_or_404(db, machine, backup_id)
    form = await request.form()
    back = f"{docker_base(machine)}/backups/{backup.id}"
    snapshot = str(form.get("snapshot") or "")
    if str(form.get("confirm_name") or "").strip() != machine.name:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.backup.restore",
            f'Refused to restore Docker backup "{backup.name}": machine name not confirmed',
            denied=True,
            details={"backup": backup.name, "snapshot": snapshot},
        )
        return redirect(back, error=LocalizedText(request, "docker.backup.confirm_mismatch"))
    volumes = [str(v) for v in form.getlist("volume")]
    paths = [str(p) for p in form.getlist("path")]
    try:
        job = await docker_actions.restore_backup(
            db,
            machine,
            backup,
            snapshot,
            started_by=actor(current_user),
            volumes=volumes,
            paths=paths,
            delete=form.get("delete") == "1",
        )
    except docker_jobs.ProtectedError:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.backup.restore",
            f'Refused to restore Docker backup "{backup.name}": debcontrol uses those volumes',
            denied=True,
            details={"backup": backup.name, "snapshot": snapshot},
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
        "machine.docker.backup.restore",
        f'Started restoring snapshot {snapshot[:12]} of Docker backup "{backup.name}" '
        f'on "{machine.name}"',
        details={
            "backup": backup.name,
            "snapshot": snapshot,
            "volumes": volumes,
            "paths": paths,
            "delete": form.get("delete") == "1",
        },
    )
    return redirect(f"{docker_base(machine)}/jobs/{job.id}")


@router.post(
    "/{machine_id}/docker/backups/{backup_id}/{what}",
    dependencies=[need_updates, Depends(verify_csrf)],
)
async def docker_backup_job(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    what: str,
    read_data_percent: int = Form(0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Run the backup now, check its repository, or prune it to its
    retention."""
    if what not in docker_actions.BACKUP_JOB_KINDS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    machine = await _get_machine_or_404(machine_id, db, current_user)
    backup = await _backup_or_404(db, machine, backup_id)
    back = f"{docker_base(machine)}/backups/{backup.id}"
    try:
        job = await docker_actions.backup_job(
            db,
            machine,
            backup,
            what,
            started_by=actor(current_user),
            read_data_percent=read_data_percent,
        )
    except docker_jobs.ProtectedError:
        return redirect(back, error=LocalizedText(request, "docker.protected"))
    except DockerCommandError as exc:
        return redirect(back, error=str(exc))
    if job is None:
        return redirect(back, error=LocalizedText(request, "docker.job.already_queued"))
    await _audit(
        db,
        request,
        machine,
        f"machine.docker.backup.{what}",
        f'Started Docker backup job "{what}" of "{backup.name}" on "{machine.name}"',
        details={"backup": backup.name},
    )
    return redirect(f"{docker_base(machine)}/jobs/{job.id}")


@router.get("/{machine_id}/docker/backups/{backup_id}/snapshots")
async def docker_backup_snapshots(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The repository's snapshots of this backup, read live."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    backup = await _backup_or_404(db, machine, backup_id)
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(
        request,
        docker_tasks.docker_backup_snapshots.delay(str(backup.id)),
        app_settings.ssh_connect_timeout + 330,
    )
    return render_partial(
        request,
        "machines/docker/_snapshots_panel.html",
        {
            "machine": machine,
            "docker_base": docker_base(machine),
            "backup": backup,
            "snapshots": (result or {}).get("snapshots") or [] if error is None else [],
            "error": error,
            "can_terminal": current_user.has_permission(Permission.ACTION_TERMINAL),
            "csrf_token": request.state.csrf_token,
        },
    )
