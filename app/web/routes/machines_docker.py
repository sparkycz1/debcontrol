"""A machine's Docker tab: containers (with their charts), one container,
images and their vulnerability scans, clean-up, volumes, networks, and
the Docker jobs (`DockerJob`) with their live output.

Pages that show what is on the machine right now (images, volumes,
networks, one container) render at once and load that part from a
worker (`app.tasks.docker_jobs.docker_inventory`) with htmx; the
containers page reads the latest monitoring sample, like before. See
`machines_docker_common` for who may do what.
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import quote

from fastapi import Depends, Form, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import DockerJob, DockerJobKind
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import (
    docker_acceptances,
    docker_actions,
    docker_jobs,
    docker_overview,
    docker_scans,
    monitoring_history,
)
from app.services.docker_gate import GATES
from app.services.update_policy import POLICIES
from app.ssh.docker_cli import (
    DockerCommandError,
    is_container_name_valid,
    is_image_id_valid,
    is_image_valid,
    is_network_name_valid,
)
from app.ssh.docker_prune import PruneOptions
from app.tasks import docker_jobs as docker_tasks
from app.web.messages import LocalizedText
from app.web.redirects import safe_local_path
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
from app.web.templating import t
from app.web.time_window import window_from_query, window_query

router = machines_router()

_INVENTORY_WAIT_EXTRA = 90


async def _inventory(
    request: Request, db: AsyncSession, machine: Machine, sections: list[str]
) -> tuple[dict[str, Any] | None, str | None]:
    app_settings = await get_or_create_app_settings(db)
    extra = 200 if "volume_sizes" in sections else _INVENTORY_WAIT_EXTRA
    result, error = await wait_task(
        request,
        docker_tasks.docker_inventory.delay(str(machine.id), sections),
        app_settings.ssh_connect_timeout + extra,
    )
    if error is not None or result is None:
        return None, error
    inventory: dict[str, Any] = result.get("inventory") or {}
    return inventory, None


def _protected_error(request: Request) -> str:
    return LocalizedText(request, "docker.protected")


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


# --- Containers --------------------------------------------------------------


@router.get("/{machine_id}/docker")
async def docker_containers_page(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    start: str = "",
    end: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The containers of the latest monitoring sample, with their CPU,
    memory and network charts over the chosen window, update and scan
    state, and what can be done with each."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    window = window_from_query(range_key, start, end)
    history, _availability = await monitoring_history.load_machine_history(
        db, machine.id, window
    )
    settings = await docker_jobs.container_settings(db, machine.id)
    scans = await docker_scans.scans_by_image(db, machine.id)
    scans_by_ref = {scan.image_ref: scan for scan in scans.values() if scan.image_ref}
    jobs = await docker_jobs.list_jobs(
        db,
        machine.id,
        limit=200,
        kinds=(DockerJobKind.CONTAINER_UPDATE, DockerJobKind.CONTAINER_ROLLBACK),
    )
    last_jobs: dict[str, DockerJob] = {}
    for job in jobs:
        last_jobs.setdefault(job.target, job)
    protected = await docker_jobs.protected_project(db, machine)
    containers = docker_overview.containers_of(machine)
    return render(
        request,
        "machines/docker/containers.html",
        machine,
        current_user,
        "containers",
        {
            "history": history,
            "window": window,
            "window_query": window_query(window),
            "time_ranges": monitoring_history.TIME_RANGES,
            "settings": settings,
            "scans_by_ref": scans_by_ref,
            "last_jobs": last_jobs,
            "protected_project": protected,
            "has_active_jobs": await docker_jobs.has_active_jobs(db, machine.id),
            "overview": {
                str(c.get("name")): docker_overview.describe(machine, c) for c in containers
            },
            "state_counts": docker_overview.state_counts(containers),
            "state_groups": docker_overview.STATE_GROUPS,
        },
    )


@router.get("/{machine_id}/docker/containers/{name}")
async def docker_container_page(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not is_container_name_valid(name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such container.")
    settings = (await docker_jobs.container_settings(db, machine.id)).get(name)
    jobs = await docker_jobs.list_jobs(db, machine.id, limit=20, target=name)
    last = docker_jobs.last_update(jobs, name)
    protected = await docker_jobs.protected_project(db, machine)
    return render(
        request,
        "machines/docker/container.html",
        machine,
        current_user,
        "containers",
        {
            "name": name,
            "setting": settings,
            "gates": GATES,
            "update_policies": POLICIES,
            "jobs": jobs,
            "rollback_image": docker_jobs.rollback_image(last),
            "is_protected": bool(protected)
            and docker_jobs.container_project(machine, name) == protected,
        },
    )


@router.get("/{machine_id}/docker/containers/{name}/panel")
async def docker_container_panel(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The container as `docker inspect` describes it right now."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    inventory, error = await _inventory(request, db, machine, ["inspect", "images"])
    container = None
    image = None
    if inventory is not None:
        container = next(
            (c for c in inventory.get("containers") or [] if c.get("name") == name), None
        )
        if container is not None:
            image = next(
                (
                    i
                    for i in inventory.get("images") or []
                    if i.get("id") == container.get("image_id")
                ),
                None,
            )
    scan = None
    if container is not None and container.get("image_id"):
        scan = await docker_scans.get_scan(db, machine.id, str(container["image_id"]))
    sampled = next(
        (c for c in docker_overview.containers_of(machine) if c.get("name") == name), None
    )
    return render_partial(
        request,
        "machines/docker/_container_panel.html",
        {
            "machine": machine,
            "docker_base": docker_base(machine),
            "container": container,
            "image": image,
            "scan": scan,
            "overview": docker_overview.describe(machine, sampled) if sampled else None,
            "error": error,
            "can_power": current_user.has_permission(Permission.ACTION_POWER),
            "can_updates": current_user.has_permission(Permission.ACTION_UPDATES),
            "can_terminal": current_user.has_permission(Permission.ACTION_TERMINAL),
            "csrf_token": request.state.csrf_token,
        },
    )


@router.get("/{machine_id}/docker/containers/{name}/shell", dependencies=[need_terminal])
async def docker_container_shell(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """A shell inside the container — the machine terminal's WebSocket with
    `?container=` (`app.web.routes.terminal_ws`), so the same permission,
    time limit, recording and audit apply."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not is_container_name_valid(name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such container.")
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before opening a terminal.",
        )
    return render(
        request,
        "machines/docker/shell.html",
        machine,
        current_user,
        "containers",
        {
            "name": name,
            "ws_path": f"/machines/{machine.id}/terminal/ws?container={quote(name, safe='')}",
            "recording": (await get_or_create_app_settings(db)).terminal_recording_enabled,
        },
    )


@router.post(
    "/{machine_id}/docker/containers/{name}/settings",
    dependencies=[need_updates, Depends(verify_csrf)],
)
async def docker_container_settings(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    auto_update: str = Form(""),
    gate: str = Form("off"),
    update_policy: str = Form("any"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Whether the "Update Docker containers" schedule updates this
    container, how far such an update may go (`app.services.
    update_policy`), and which vulnerabilities stop its updates."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not is_container_name_valid(name) or gate not in GATES or update_policy not in POLICIES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")
    await docker_jobs.save_container_setting(
        db,
        machine.id,
        name,
        auto_update=auto_update == "1",
        gate=gate,
        actor=actor(current_user),
        update_policy=update_policy,
    )
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.container.settings",
        f'Docker settings of container "{name}" on "{machine.name}": '
        f"auto-update {'on' if auto_update == '1' else 'off'} ({update_policy}), gate {gate}",
        details={
            "container": name,
            "auto_update": auto_update == "1",
            "update_policy": update_policy,
            "gate": gate,
        },
    )
    return redirect(
        f"{docker_base(machine)}/containers/{name}",
        notice=LocalizedText(request, "docker.container.settings_saved"),
    )


async def _queue_updates(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    user: User,
    names: list[str],
    gate: str,
) -> tuple[docker_actions.Queued, str | None]:
    queued = await docker_actions.update_containers(
        db, machine, names, started_by=actor(user), gate=gate or None
    )
    for job in queued.jobs:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.container.update",
            f'Started updating container "{job.target}" on "{machine.name}"',
            details={"container": job.target, "gate": (job.params or {}).get("gate")},
        )
    for name, reason in queued.skipped.items():
        if reason == "protected":
            await _audit(
                db,
                request,
                machine,
                "machine.docker.container.update",
                f'Refused to update container "{name}" on "{machine.name}": debcontrol runs in it',
                denied=True,
                details={"container": name, "reason": reason},
            )
    error = None
    if "protected" in queued.skipped.values():
        error = _protected_error(request)
    elif not queued.jobs and queued.skipped:
        error = LocalizedText(request, "docker.job.already_queued")
    return queued, error


@router.post(
    "/{machine_id}/docker/containers/{name}/update",
    dependencies=[need_updates, Depends(verify_csrf)],
)
async def docker_container_update(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    gate: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not is_container_name_valid(name) or (gate and gate not in GATES):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")
    queued, error = await _queue_updates(request, db, machine, current_user, [name], gate)
    if queued.jobs:
        return redirect(f"{docker_base(machine)}/jobs/{queued.jobs[0].id}")
    return redirect(f"{docker_base(machine)}/containers/{name}", error=error)


@router.post("/{machine_id}/docker/update", dependencies=[need_updates, Depends(verify_csrf)])
async def docker_update_many(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Update selected" / "Update all with a newer image" on the
    containers page — one job per container, run one after another."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    form = await request.form()
    names = [str(v) for v in form.getlist("container") if is_container_name_valid(str(v))]
    if form.get("scope") == "with_update":
        updates = machine.docker_image_updates or {}
        names = [
            str(c.get("name"))
            for c in machine.docker_containers or []
            if isinstance(c, dict) and updates.get(str(c.get("image"))) == "update"
        ]
    if not names:
        return redirect(
            docker_base(machine), error=LocalizedText(request, "docker.update.none_selected")
        )
    queued, error = await _queue_updates(request, db, machine, current_user, names, "")
    notice = (
        LocalizedText(request, "docker.update.queued", count=len(queued.jobs))
        if queued.jobs
        else None
    )
    return redirect(f"{docker_base(machine)}/jobs", notice=notice, error=error)


# What the selected rows' buttons need: start/stop/restart are power
# actions, like a single container's; update, scan and remove change what
# is installed, like an update or a clean-up.
_BULK_PERMISSION = {
    "start": Permission.ACTION_POWER,
    "stop": Permission.ACTION_POWER,
    "restart": Permission.ACTION_POWER,
    "remove": Permission.ACTION_UPDATES,
    "scan": Permission.ACTION_UPDATES,
    "update": Permission.ACTION_UPDATES,
}


@router.post("/{machine_id}/docker/containers/bulk", dependencies=[Depends(verify_csrf)])
async def docker_containers_bulk(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The buttons under the containers table, for the selected rows:
    start, stop, restart, remove (stopped ones), scan their images, or
    update them. Each needs the same permission as doing it to one."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    form = await request.form()
    action = str(form.get("action") or "")
    permission = _BULK_PERMISSION.get(action)
    if permission is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")
    if not current_user.has_permission(permission):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    names = [str(v) for v in form.getlist("container") if is_container_name_valid(str(v))]
    if not names:
        return redirect(
            docker_base(machine), error=LocalizedText(request, "docker.bulk.none_selected")
        )
    if action == "update":
        queued, update_error = await _queue_updates(
            request, db, machine, current_user, names, ""
        )
        update_notice = (
            LocalizedText(request, "docker.update.queued", count=len(queued.jobs))
            if queued.jobs
            else None
        )
        return redirect(f"{docker_base(machine)}/jobs", notice=update_notice, error=update_error)
    if action == "scan":
        images = {
            str(c.get("image"))
            for c in docker_overview.containers_of(machine)
            if c.get("name") in names and c.get("image")
        }
        try:
            job = await docker_actions.scan_images(
                db, machine, started_by=actor(current_user), refs=sorted(images)
            )
        except DockerCommandError:
            return redirect(
                docker_base(machine), error=LocalizedText(request, "docker.bulk.none_selected")
            )
        if job is None:
            return redirect(
                docker_base(machine), error=LocalizedText(request, "docker.job.already_queued")
            )
        await _audit(
            db,
            request,
            machine,
            "machine.docker.images.scan",
            f'Started a vulnerability scan ({job.target}) on "{machine.name}"',
            details={"target": job.target},
        )
        return redirect(f"{docker_base(machine)}/jobs/{job.id}")

    app_settings = await get_or_create_app_settings(db)
    result = await docker_actions.run_bulk_action(
        db, machine, action, names, timeout=app_settings.ssh_connect_timeout + 120
    )
    for name in result.names:
        await _audit(
            db,
            request,
            machine,
            f"machine.container.{action}",
            f'Container "{name}" {action} on "{machine.name}"',
            ok=result.error is None,
            details={"container": name, **({"error": result.error} if result.error else {})},
        )
    for name, reason in result.skipped.items():
        if reason == "protected":
            await _audit(
                db,
                request,
                machine,
                f"machine.container.{action}",
                f'Refused to {action} container "{name}" on "{machine.name}": '
                "debcontrol runs in it",
                denied=True,
                details={"container": name, "reason": reason},
            )
    error: str | None = result.error
    if error is None and "protected" in result.skipped.values():
        error = _protected_error(request)
    notice = (
        LocalizedText(
            request, f"docker.bulk.done_{action}", count=len(result.names)
        )
        if result.names and result.error is None
        else None
    )
    return redirect(docker_base(machine), notice=notice, error=error)


@router.post(
    "/{machine_id}/docker/containers/{name}/rollback",
    dependencies=[need_updates, Depends(verify_csrf)],
)
async def docker_container_rollback(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Back to the image the container ran before its last update."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not is_container_name_valid(name):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")
    jobs = await docker_jobs.list_jobs(db, machine.id, limit=20, target=name)
    last = docker_jobs.last_update(jobs, name)
    image_id = docker_jobs.rollback_image(last)
    base = f"{docker_base(machine)}/containers/{name}"
    if image_id is None:
        return redirect(base, error=LocalizedText(request, "docker.rollback.nothing"))
    try:
        job = await docker_actions.rollback_container(
            db,
            machine,
            name,
            image_id,
            started_by=actor(current_user),
            ref=docker_jobs.rollback_ref(last),
        )
    except docker_jobs.ProtectedError:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.container.rollback",
            f'Refused to roll back container "{name}" on "{machine.name}": debcontrol runs in it',
            denied=True,
            details={"container": name},
        )
        return redirect(base, error=_protected_error(request))
    except DockerCommandError:
        return redirect(base, error=LocalizedText(request, "docker.rollback.nothing"))
    if job is None:
        return redirect(base, error=LocalizedText(request, "docker.job.already_queued"))
    await _audit(
        db,
        request,
        machine,
        "machine.docker.container.rollback",
        f'Started rolling back container "{name}" on "{machine.name}"',
        details={"container": name, "image_id": image_id},
    )
    return redirect(f"{docker_base(machine)}/jobs/{job.id}")


# --- Images -----------------------------------------------------------------


@router.get("/{machine_id}/docker/images")
async def docker_images_page(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    return render(request, "machines/docker/images.html", machine, current_user, "images")


@router.get("/{machine_id}/docker/images/panel")
async def docker_images_panel(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    inventory, error = await _inventory(request, db, machine, ["images", "inspect", "df"])
    scans = await docker_scans.scans_by_image(db, machine.id)
    await db.refresh(machine)
    images = (inventory or {}).get("images") or []
    containers = (inventory or {}).get("containers") or []
    return render_partial(
        request,
        "machines/docker/_images_panel.html",
        {
            "machine": machine,
            "docker_base": docker_base(machine),
            "images": images,
            "containers": containers,
            "df": (inventory or {}).get("df") or {},
            "scans": scans,
            "error": error,
            "can_updates": current_user.has_permission(Permission.ACTION_UPDATES),
            "csrf_token": request.state.csrf_token,
            "prune_preview": {
                "dangling": [i for i in images if i.get("dangling") and not i.get("in_use")],
                "unused": [i for i in images if not i.get("in_use")],
                "stopped": [c for c in containers if not c.get("running")],
            },
        },
    )


@router.post("/{machine_id}/docker/images/scan", dependencies=[need_updates, Depends(verify_csrf)])
async def docker_images_scan(
    request: Request,
    machine_id: uuid.UUID,
    image: str = Form(""),
    image_id: str = Form(""),
    scope: str = Form(""),
    back: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Scan one image (`image` + `image_id`) or a scope of them with
    Trivy and Grype, both pulled fresh."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    try:
        if image or image_id:
            if not is_image_valid(image) or not is_image_id_valid(image_id):
                raise DockerCommandError("Invalid image.")
            job = await docker_actions.scan_images(
                db, machine, started_by=actor(current_user), images={image: image_id}
            )
        else:
            job = await docker_actions.scan_images(
                db, machine, started_by=actor(current_user), scope=scope
            )
    except DockerCommandError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    # Back to the page the scan was started from, if it is one of this
    # machine's Docker pages.
    default_back = f"{docker_base(machine)}/images"
    target_back = safe_local_path(back, default_back)
    if not target_back.startswith(f"{docker_base(machine)}/"):
        target_back = default_back
    if job is None:
        return redirect(target_back, error=LocalizedText(request, "docker.job.already_queued"))
    await _audit(
        db,
        request,
        machine,
        "machine.docker.images.scan",
        f'Started a vulnerability scan ({job.target}) on "{machine.name}"',
        details={"target": job.target},
    )
    return redirect(f"{docker_base(machine)}/jobs/{job.id}")


@router.get("/{machine_id}/docker/images/{image_id}/vulnerabilities")
async def docker_image_vulnerabilities(
    request: Request,
    machine_id: uuid.UUID,
    image_id: str,
    severity: str = "",
    q: str = "",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not is_image_id_valid(image_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such image.")
    scan = await docker_scans.get_scan(db, machine.id, image_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No scan of this image.")
    findings = list(scan.vulnerabilities or [])
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    needle = q.strip().lower()
    if needle:
        findings = [
            f
            for f in findings
            if needle in str(f.get("id", "")).lower() or needle in str(f.get("pkg", "")).lower()
        ]
    return render(
        request,
        "machines/docker/vulnerabilities.html",
        machine,
        current_user,
        "images",
        {
            "scan": scan,
            "findings": findings,
            "severity": severity,
            "q": q,
            # Accepted critical/high ones (`app.services.docker_acceptances`).
            "accepted": docker_acceptances.accepted_for(
                await docker_acceptances.active(db), scan.image_ref
            ),
        },
    )


@router.post("/{machine_id}/docker/prune", dependencies=[need_updates, Depends(verify_csrf)])
async def docker_prune(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Clean up what the checkboxes select (`app.ssh.docker_prune`).
    Removing named volumes also needs the machine's name typed."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    form = await request.form()
    options = PruneOptions(
        containers=form.get("containers") == "1",
        images=form.get("images") == "1",
        all_images=form.get("all_images") == "1",
        networks=form.get("networks") == "1",
        volumes=form.get("volumes") == "1",
        all_volumes=form.get("all_volumes") == "1",
        build_cache=form.get("build_cache") == "1",
    )
    back = f"{docker_base(machine)}/images"
    if not options.anything:
        return redirect(back, error=LocalizedText(request, "docker.prune.nothing"))
    if options.all_volumes and (
        not options.volumes or str(form.get("confirm_name") or "").strip() != machine.name
    ):
        await _audit(
            db,
            request,
            machine,
            "machine.docker.prune",
            f'Refused to remove all unused volumes on "{machine.name}": name not confirmed',
            denied=True,
            details=options.as_dict(),
        )
        return redirect(back, error=LocalizedText(request, "docker.prune.confirm_mismatch"))
    job = await docker_actions.prune(db, machine, options, started_by=actor(current_user))
    if job is None:
        return redirect(back, error=LocalizedText(request, "docker.job.already_queued"))
    await _audit(
        db,
        request,
        machine,
        "machine.docker.prune",
        f'Started a Docker clean-up on "{machine.name}"',
        details=options.as_dict(),
    )
    return redirect(f"{docker_base(machine)}/jobs/{job.id}")


# --- Volumes and networks -----------------------------------------------------


@router.get("/{machine_id}/docker/volumes")
async def docker_volumes_page(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    return render(request, "machines/docker/volumes.html", machine, current_user, "volumes")


@router.get("/{machine_id}/docker/volumes/panel")
async def docker_volumes_panel(
    request: Request,
    machine_id: uuid.UUID,
    sizes: str = "",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    sections = ["volumes", "inspect"] + (["volume_sizes"] if sizes == "1" else [])
    inventory, error = await _inventory(request, db, machine, sections)
    return render_partial(
        request,
        "machines/docker/_volumes_panel.html",
        {
            "machine": machine,
            "docker_base": docker_base(machine),
            "volumes": (inventory or {}).get("volumes") or [],
            "with_sizes": sizes == "1",
            "error": error,
            "can_terminal": current_user.has_permission(Permission.ACTION_TERMINAL),
        },
    )


@router.get("/{machine_id}/docker/networks")
async def docker_networks_page(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    return render(request, "machines/docker/networks.html", machine, current_user, "networks")


@router.get("/{machine_id}/docker/networks/panel")
async def docker_networks_panel(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    inventory, error = await _inventory(request, db, machine, ["networks", "inspect"])
    return render_partial(
        request,
        "machines/docker/_networks_panel.html",
        {
            "machine": machine,
            "docker_base": docker_base(machine),
            "networks": (inventory or {}).get("networks") or [],
            "error": error,
        },
    )


@router.get("/{machine_id}/docker/networks/{name}")
async def docker_network_page(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not is_network_name_valid(name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such network.")
    return render(
        request, "machines/docker/network.html", machine, current_user, "networks", {"name": name}
    )


@router.get("/{machine_id}/docker/networks/{name}/panel")
async def docker_network_panel(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The network as `docker network inspect` describes it right now."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not is_network_name_valid(name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such network.")
    inventory, error = await _inventory(request, db, machine, ["network_inspect"])
    network = next(
        (n for n in (inventory or {}).get("network_details") or [] if n.get("name") == name),
        None,
    )
    return render_partial(
        request,
        "machines/docker/_network_panel.html",
        {
            "machine": machine,
            "docker_base": docker_base(machine),
            "network": network,
            "name": name,
            "error": error,
        },
    )


# --- Jobs -------------------------------------------------------------------


@router.get("/{machine_id}/docker/jobs")
async def docker_jobs_page(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    jobs = await docker_jobs.list_jobs(db, machine.id)
    return render(
        request, "machines/docker/jobs.html", machine, current_user, "jobs", {"jobs": jobs}
    )


@router.get("/{machine_id}/docker/jobs/panel")
async def docker_jobs_panel(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The job list again, for its live refresh while jobs are running."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    jobs = await docker_jobs.list_jobs(db, machine.id)
    return render_partial(
        request,
        "machines/docker/_jobs_list.html",
        {"machine": machine, "docker_base": docker_base(machine), "jobs": jobs},
    )


async def _job_or_404(db: AsyncSession, machine: Machine, job_id: uuid.UUID) -> DockerJob:
    job = await docker_jobs.get_job(db, machine.id, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
    return job


@router.get("/{machine_id}/docker/jobs/{job_id}")
async def docker_job_page(
    request: Request,
    machine_id: uuid.UUID,
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    job = await _job_or_404(db, machine, job_id)
    return render(
        request,
        "machines/docker/job.html",
        machine,
        current_user,
        "jobs",
        {"job": job, "output_hidden": docker_jobs.output_hidden(job, current_user)},
    )


@router.get("/{machine_id}/docker/jobs/{job_id}/status")
async def docker_job_status(
    request: Request,
    machine_id: uuid.UUID,
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    job = await _job_or_404(db, machine, job_id)
    return render_partial(
        request,
        "machines/docker/_job_status.html",
        {
            "machine": machine,
            "docker_base": docker_base(machine),
            "job": job,
            "output_hidden": docker_jobs.output_hidden(job, current_user),
        },
    )


def job_label(request: Request, job: DockerJob) -> str:
    return t(request, f"docker.job.kind.{job.kind}")
