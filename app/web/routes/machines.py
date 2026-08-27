"""Managed machines — CRUD, host key pinning, connection testing."""

from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.session import get_db
from app.schemas.machine import MachineCreate
from app.ssh.client import discover_host_key_fingerprint
from app.ssh.exceptions import SSHConnectionError
from app.web.templating import templates

router = APIRouter(prefix="/machines")

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


@router.get("")
async def list_machines(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(
        select(Machine).options(selectinload(Machine.group)).order_by(Machine.hostname)
    )
    machines = result.scalars().all()
    return templates.TemplateResponse(request, "machines/list.html", {"machines": machines})


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
            "form": {},
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_machine(
    request: Request,
    db: AsyncSession = Depends(get_db),
    hostname: str = Form(...),
    port: int = Form(22),
    username: str = Form(...),
    auth_method: AuthMethod = Form(...),
    secret: str = Form(""),
    group_id: str = Form(""),
    description: str = Form(""),
) -> Response:
    try:
        payload = MachineCreate(
            hostname=hostname,
            port=port,
            username=username,
            auth_method=auth_method,
            secret=secret or None,
            group_id=uuid.UUID(group_id) if group_id else None,
            description=description or None,
        )
    except ValueError as exc:
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machines/new.html",
            {
                "auth_methods": list(AuthMethod),
                "groups": await _get_groups(db),
                "errors": [str(exc)],
                "form": {
                    "hostname": hostname,
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
        hostname=payload.hostname,
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

    return RedirectResponse(url=f"/machines/{machine.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{machine_id}")
async def machine_detail(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request, "machines/detail.html", {"machine": machine, "csrf_token": csrf_token}
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/discover-host-key", dependencies=[Depends(verify_csrf)])
async def discover_host_key(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()
    csrf_token, new_cookie = get_or_create_csrf_token(request)

    context: dict[str, object] = {"machine": machine, "csrf_token": csrf_token}
    try:
        context["fingerprint"] = await discover_host_key_fingerprint(
            machine.hostname, machine.port, settings.ssh_connect_timeout
        )
    except SSHConnectionError as exc:
        context["error"] = str(exc)

    response = templates.TemplateResponse(request, "partials/host_key_discovery.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/trust-host-key", dependencies=[Depends(verify_csrf)])
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

    redirect_url = f"/machines/{machine.id}"
    # The fingerprint-confirmation form only ever renders inside an htmx fragment —
    # a plain 3xx redirect would be silently followed by htmx and the returned HTML
    # would end up swapped into just that panel. HX-Redirect tells htmx to navigate
    # the whole page instead.
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{machine_id}/test-connection", dependencies=[Depends(verify_csrf)])
async def test_connection_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()

    job = await request.app.state.arq_redis.enqueue_job("ping_machine", str(machine.id))
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

    return templates.TemplateResponse(
        request,
        "partials/test_connection_result.html",
        {"machine": machine, "result": result, "error": error},
    )


@router.post("/{machine_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_machine(machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    await db.delete(machine)
    await db.commit()
    return RedirectResponse(url="/machines", status_code=status.HTTP_303_SEE_OTHER)
