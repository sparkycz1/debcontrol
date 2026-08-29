"""Managed machines — CRUD, host key pinning, connection testing, facts."""

from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_permission
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_update_run import MachineUpdateRun, UpgradeStrategy
from app.db.models.pending_machine import PendingMachine
from app.db.models.role import Permission
from app.db.session import get_db
from app.schemas.machine import MachineCreate, MachineUpdate
from app.ssh.client import discover_host_key_fingerprint
from app.ssh.exceptions import SSHConnectionError
from app.ssh.power import PowerAction
from app.web.machine_search import machine_search_clause
from app.web.templating import templates

router = APIRouter(
    prefix="/machines", dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))]
)
_manage = Depends(require_permission(Permission.MACHINE_MANAGE))
_updates = Depends(require_permission(Permission.ACTION_UPDATES))
_power = Depends(require_permission(Permission.ACTION_POWER))

# Fingerprint shaped like "SHA256:<base64...>", as returned by AsyncSSH/OpenSSH.
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9]+:[A-Za-z0-9+/=_-]+$")


async def _get_machine_or_404(machine_id: uuid.UUID, db: AsyncSession) -> Machine:
    # Eager-load `group` — templates read `machine.group` and the async ORM
    # can't lazy-load relationships outside of an `await` (it would raise
    # MissingGreenlet during template rendering).
    result = await db.execute(
        select(Machine).options(selectinload(Machine.group)).where(Machine.id == machine_id)
    )
    machine = result.scalar_one_or_none()
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found.")
    return machine


async def _get_groups(db: AsyncSession) -> list[MachineGroup]:
    result = await db.execute(select(MachineGroup).order_by(MachineGroup.name))
    return list(result.scalars().all())


async def _get_pending_machines(db: AsyncSession) -> list[PendingMachine]:
    result = await db.execute(select(PendingMachine).order_by(PendingMachine.created_at.desc()))
    return list(result.scalars().all())


async def _get_recent_update_runs(
    machine_id: uuid.UUID, db: AsyncSession, limit: int = 5
) -> list[MachineUpdateRun]:
    result = await db.execute(
        select(MachineUpdateRun)
        .where(MachineUpdateRun.machine_id == machine_id)
        .order_by(MachineUpdateRun.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def _get_update_run_or_404(run_id: uuid.UUID, db: AsyncSession) -> MachineUpdateRun:
    run = await db.get(MachineUpdateRun, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return run


@router.get("")
async def list_machines(
    request: Request, db: AsyncSession = Depends(get_db), q: str = ""
) -> Response:
    query = select(Machine).options(selectinload(Machine.group))
    if q.strip():
        query = query.where(machine_search_clause(q))
    result = await db.execute(query.order_by(Machine.name))
    machines = result.scalars().all()
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/list.html",
        {
            "machines": machines,
            "pending_machines": await _get_pending_machines(db),
            "q": q,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/new")
async def new_machine_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/new.html",
        {
            "auth_methods": list(AuthMethod),
            "groups": await _get_groups(db),
            "errors": [],
            "form": {
                "name": request.query_params.get("name", ""),
                "ip_address": request.query_params.get("ip_address", ""),
            },
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("", dependencies=[_manage, Depends(verify_csrf)])
async def create_machine(
    request: Request,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    ip_address: str = Form(...),
    port: int = Form(22),
    username: str = Form(...),
    auth_method: AuthMethod = Form(...),
    secret: str = Form(""),
    group_id: str = Form(""),
    description: str = Form(""),
) -> Response:
    try:
        payload = MachineCreate(
            name=name,
            ip_address=ip_address,
            port=port,
            username=username,
            auth_method=auth_method,
            secret=secret or None,
            group_id=uuid.UUID(group_id) if group_id else None,
            description=description or None,
        )
    except ValueError as exc:
        await log_event(
            db,
            request=request,
            action="machine.create",
            summary=f'Rejected new machine "{name}": {exc}',
            outcome=AuditOutcome.FAILURE,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machines/new.html",
            {
                "auth_methods": list(AuthMethod),
                "groups": await _get_groups(db),
                "errors": [str(exc)],
                "form": {
                    "name": name,
                    "ip_address": ip_address,
                    "port": port,
                    "username": username,
                    "auth_method": auth_method,
                    "description": description,
                },
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    machine = Machine(
        name=payload.name,
        ip_address=payload.ip_address,
        port=payload.port,
        username=payload.username,
        auth_method=payload.auth_method,
        secret_encrypted=encrypt_secret(payload.secret) if payload.secret else None,
        group_id=payload.group_id,
        description=payload.description,
    )
    db.add(machine)
    await db.commit()
    await db.refresh(machine)

    await log_event(
        db,
        request=request,
        action="machine.create",
        summary=f'Created machine "{machine.name}" ({machine.ip_address})',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )

    return RedirectResponse(url=f"/machines/{machine.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{machine_id}")
async def machine_detail(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/detail.html",
        {
            "machine": machine,
            "csrf_token": csrf_token,
            "update_runs": await _get_recent_update_runs(machine_id, db),
            # One-time notice after a power action redirect — not persisted
            # anywhere, just echoed back from the query string.
            "power_sent": request.query_params.get("power_sent"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{machine_id}/edit")
async def edit_machine_form(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/edit.html",
        {
            "machine": machine,
            "auth_methods": list(AuthMethod),
            "groups": await _get_groups(db),
            "errors": [],
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/edit", dependencies=[_manage, Depends(verify_csrf)])
async def update_machine(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    ip_address: str = Form(...),
    port: int = Form(22),
    username: str = Form(...),
    auth_method: AuthMethod = Form(...),
    secret: str = Form(""),
    group_id: str = Form(""),
    description: str = Form(""),
    is_active: str = Form(""),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)

    try:
        payload = MachineUpdate(
            name=name,
            ip_address=ip_address,
            port=port,
            username=username,
            auth_method=auth_method,
            secret=secret or None,
            group_id=uuid.UUID(group_id) if group_id else None,
            description=description or None,
            # HTML only sends a checkbox field when it's checked.
            is_active=bool(is_active),
        )
    except ValueError as exc:
        await log_event(
            db,
            request=request,
            action="machine.update",
            summary=f'Rejected update to "{machine.name}": {exc}',
            outcome=AuditOutcome.FAILURE,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machines/edit.html",
            {
                "machine": machine,
                "auth_methods": list(AuthMethod),
                "groups": await _get_groups(db),
                "errors": [str(exc)],
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    # Changing where/how we connect invalidates the trust and facts we
    # previously established for whatever was at the old address — force
    # host-key re-discovery/re-confirmation rather than silently keeping
    # trust that no longer applies to the same physical/logical machine.
    connection_target_changed = (
        payload.ip_address != machine.ip_address or payload.port != machine.port
    )

    machine.name = payload.name
    machine.ip_address = payload.ip_address
    machine.port = payload.port
    machine.username = payload.username
    machine.auth_method = payload.auth_method
    machine.group_id = payload.group_id
    machine.description = payload.description
    machine.is_active = payload.is_active

    if payload.auth_method == AuthMethod.PASSWORD:
        if payload.secret:
            machine.secret_encrypted = encrypt_secret(payload.secret)
        # else: keep whatever password is already stored, unchanged.
    else:
        # SSH_KEY doesn't need a per-machine secret — don't leave a stale
        # password sitting around encrypted but unused.
        machine.secret_encrypted = None

    if connection_target_changed:
        machine.host_key_fingerprint = None
        machine.discovered_hostname = None
        machine.os_version = None
        machine.kernel_version = None
        machine.cpu_cores = None
        machine.ram_bytes = None
        machine.disks = None
        machine.facts_updated_at = None

    await db.commit()

    await log_event(
        db,
        request=request,
        action="machine.update",
        summary=f'Updated machine "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"connection_target_changed": connection_target_changed},
    )

    return RedirectResponse(url=f"/machines/{machine.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{machine_id}/discover-host-key", dependencies=[_manage, Depends(verify_csrf)])
async def discover_host_key(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()
    csrf_token, new_cookie = get_or_create_csrf_token(request)

    context: dict[str, object] = {"machine": machine, "csrf_token": csrf_token}
    try:
        context["fingerprint"] = await discover_host_key_fingerprint(
            machine.ip_address, machine.port, settings.ssh_connect_timeout
        )
    except SSHConnectionError as exc:
        context["error"] = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.host_key.discover",
        summary=f'Discovered host key fingerprint for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if "error" not in context else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": context["error"]} if "error" in context else None,
    )

    response = templates.TemplateResponse(request, "partials/host_key_discovery.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/trust-host-key", dependencies=[_manage, Depends(verify_csrf)])
async def trust_host_key(
    request: Request,
    machine_id: uuid.UUID,
    fingerprint: str = Form(...),
    db: AsyncSession = Depends(get_db),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    fingerprint = fingerprint.strip()
    if not _FINGERPRINT_RE.match(fingerprint):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid fingerprint format."
        )
    machine.host_key_fingerprint = fingerprint
    await db.commit()

    await log_event(
        db,
        request=request,
        action="machine.host_key.trust",
        summary=f'Trusted host key fingerprint for "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"fingerprint": fingerprint},
    )

    # Now that the machine can be safely connected to, kick off an initial
    # facts gathering pass in the background — don't block the redirect on it.
    await request.app.state.arq_redis.enqueue_job("refresh_machine_facts", str(machine.id))

    redirect_url = f"/machines/{machine.id}"
    # The fingerprint-confirmation form only ever renders inside an htmx fragment —
    # a plain 3xx redirect would be silently followed by htmx and the returned HTML
    # would end up swapped into just that panel. HX-Redirect tells htmx to navigate
    # the whole page instead.
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{machine_id}/test-connection", dependencies=[_manage, Depends(verify_csrf)])
async def test_connection_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()

    job = await request.app.state.arq_redis.enqueue_job("test_machine_connection", str(machine.id))
    result: dict[str, object] | None = None
    error: str | None = None
    try:
        result = await job.result(timeout=settings.ssh_connect_timeout + 5)
    except TimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        # arq's `.result()` re-raises whatever exception happened inside the job —
        # we want to show that to the user as a test failure, not crash the request.
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.test_connection",
        summary=f'Tested connection to "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    return templates.TemplateResponse(
        request,
        "partials/test_connection_result.html",
        {"machine": machine, "result": result, "error": error},
    )


@router.post("/{machine_id}/refresh-facts", dependencies=[_manage, Depends(verify_csrf)])
async def refresh_facts_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()

    job = await request.app.state.arq_redis.enqueue_job("refresh_machine_facts", str(machine.id))
    error: str | None = None
    try:
        result = await job.result(timeout=settings.ssh_connect_timeout + 5)
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except TimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    if error is None:
        # Facts were updated in the DB by the job — reload to pick them up.
        machine = await _get_machine_or_404(machine_id, db)

    await log_event(
        db,
        request=request,
        action="machine.facts.refresh",
        summary=f'Refreshed facts for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    # The partial has its own "Refresh facts" button, which needs a CSRF
    # token too — reuse the one already set on this client rather than
    # minting (and trying to re-set) a fresh cookie from inside an htmx swap.
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/machine_facts.html",
        {"machine": machine, "error": error, "csrf_token": csrf_token},
    )


@router.post("/{machine_id}/check-updates", dependencies=[_updates, Depends(verify_csrf)])
async def check_updates_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()

    job = await request.app.state.arq_redis.enqueue_job("check_machine_updates", str(machine.id))
    error: str | None = None
    try:
        result = await job.result(timeout=settings.update_timeout_seconds + 5)
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except TimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    # Counts were updated in the DB by the job (even on failure, they're
    # reset to "unknown" rather than left stale) — reload either way.
    machine = await _get_machine_or_404(machine_id, db)

    await log_event(
        db,
        request=request,
        action="machine.updates.check",
        summary=f'Checked for updates on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/update_availability.html",
        {"machine": machine, "error": error, "csrf_token": csrf_token},
    )


@router.post("/{machine_id}/updates", dependencies=[_updates, Depends(verify_csrf)])
async def trigger_machine_update(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    if not machine.host_key_fingerprint:
        await log_event(
            db,
            request=request,
            action="machine.updates.run",
            summary=f'Blocked update on "{machine.name}": no pinned host key',
            outcome=AuditOutcome.DENIED,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before running updates.",
        )

    # apt update/upgrade can run for a long time — this only creates the
    # record and enqueues the job, it never waits for the result.
    run = MachineUpdateRun(machine_id=machine.id, strategy=strategy)
    db.add(run)
    await db.commit()
    await db.refresh(run)

    await request.app.state.arq_redis.enqueue_job("run_machine_update", str(run.id))

    await log_event(
        db,
        request=request,
        action="machine.updates.run",
        summary=f'Triggered {strategy.value.replace("_", "-")} on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"strategy": strategy.value, "run_id": str(run.id)},
    )

    return RedirectResponse(
        url=f"/machines/{machine.id}/updates/{run.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/{machine_id}/updates/{run_id}")
async def machine_update_run_detail(
    request: Request,
    machine_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    run = await _get_update_run_or_404(run_id, db)
    if run.machine_id != machine.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return templates.TemplateResponse(
        request, "machines/update_run.html", {"machine": machine, "run": run}
    )


@router.get("/{machine_id}/updates/{run_id}/status")
async def machine_update_run_status(
    request: Request,
    machine_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Pollable fragment (htmx `hx-trigger="every ...s"`) showing one run's
    status/output. Once the run reaches a terminal state, the fragment stops
    including the polling attributes, so htmx naturally stops re-fetching it.
    """
    run = await _get_update_run_or_404(run_id, db)
    if run.machine_id != machine_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return templates.TemplateResponse(
        request, "partials/update_run_status.html", {"run": run}
    )


@router.get("/{machine_id}/power/{action}")
async def power_confirm_form(
    request: Request, machine_id: uuid.UUID, action: PowerAction, db: AsyncSession = Depends(get_db)
) -> Response:
    """First confirmation step: a dedicated page stating exactly what's
    about to happen. The second step — typing the machine's name — is
    enforced server-side in `power_action`, not just disabled-until-typed
    in the browser."""
    machine = await _get_machine_or_404(machine_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/power_confirm.html",
        {"machine": machine, "action": action, "error": None, "csrf_token": csrf_token},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/power", dependencies=[_power, Depends(verify_csrf)])
async def power_action(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    action: PowerAction = Form(...),
    confirm_name: str = Form(...),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)

    if confirm_name.strip() != machine.name:
        await log_event(
            db,
            request=request,
            action=f"machine.power.{action.value}",
            summary=f'Blocked {action.value} on "{machine.name}": confirmation mismatch',
            outcome=AuditOutcome.DENIED,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machines/power_confirm.html",
            {
                "machine": machine,
                "action": action,
                "error": f'That doesn\'t match — type "{machine.name}" exactly to confirm.',
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    if not machine.host_key_fingerprint:
        await log_event(
            db,
            request=request,
            action=f"machine.power.{action.value}",
            summary=f'Blocked {action.value} on "{machine.name}": no pinned host key',
            outcome=AuditOutcome.DENIED,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before sending power commands.",
        )

    # Fire-and-forget, same reasoning as system updates: the connection can
    # legitimately drop once the machine actually reboots/shuts down, so
    # there's nothing meaningful to wait for here.
    await request.app.state.arq_redis.enqueue_job(
        "send_machine_power_command", str(machine.id), action.value
    )

    await log_event(
        db,
        request=request,
        action=f"machine.power.{action.value}",
        summary=f'Sent {action.value} to "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )

    return RedirectResponse(
        url=f"/machines/{machine.id}?power_sent={action.value}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/pending/{pending_id}/dismiss", dependencies=[_manage, Depends(verify_csrf)])
async def dismiss_pending_machine(
    request: Request, pending_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    pending = await db.get(PendingMachine, pending_id)
    if pending is not None:
        await db.delete(pending)
        await db.commit()
        await log_event(
            db,
            request=request,
            action="machine.pending.dismiss",
            summary=f'Dismissed pending machine "{pending.ip_address}"',
            target_type="pending_machine",
            target_id=pending_id,
            target_label=pending.ip_address,
        )
    return RedirectResponse(url="/machines", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{machine_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_machine(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    machine_name = machine.name
    await db.delete(machine)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machine.delete",
        summary=f'Deleted machine "{machine_name}"',
        target_type="machine",
        target_id=machine_id,
        target_label=machine_name,
    )
    return RedirectResponse(url="/machines", status_code=status.HTTP_303_SEE_OTHER)
