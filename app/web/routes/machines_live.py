"""The Overview's live part: the cards (CPU, memory, storage, network,
temperature) drawn from the newest monitoring samples, the top processes
read on demand, one process's detail, sending it TERM or KILL, and the
"Test connectivity" check run from the machine itself.

Reading processes and testing connectivity run on a worker
(`app.tasks.jobs`), so the SSH connection is the reused one and the web
process only waits for the answer. Viewing is `machine.view`; command
lines need `action.terminal` too (they can hold passwords); a signal needs
`action.power` and is audited (`machine.process.signal`)."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.permission import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import live_overview
from app.ssh import processes
from app.tasks import jobs as tasks
from app.web.messages import LocalizedText
from app.web.routes.machines_common import _get_machine_or_404, machines_router, need_power
from app.web.templating import templates

router = machines_router()

# How often the open process list asks again (seconds).
PROCESS_REFRESH_SECONDS = 5


async def _wait(result: Any, wait_seconds: int, request: Request) -> dict[str, Any]:
    """A Celery result, or `{"ok": False, "error": ...}` when it never came."""
    try:
        value = await asyncio.to_thread(result.get, timeout=wait_seconds)
    except CeleryTimeoutError:
        return {"ok": False, "error": LocalizedText(request, "common.error.job_timeout")}
    except Exception as exc:
        return {"ok": False, "error": str(exc) or type(exc).__name__}
    return value if isinstance(value, dict) else {"ok": False, "error": "Unexpected answer."}


@router.get("/{machine_id}/live-panel")
async def machine_live_panel(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    return templates.TemplateResponse(
        request,
        "partials/machine_live.html",
        await live_context(db, machine),
    )


async def live_context(db: AsyncSession, machine: Any) -> dict[str, Any]:
    """What `partials/machine_live.html` needs — also for the Overview."""
    settings = await get_or_create_app_settings(db)
    samples = await live_overview.load_recent(db, machine.id)
    return {
        "machine": machine,
        "live": live_overview.build_cards(machine, samples),
        "live_settings": settings,
    }


def _sort(value: str) -> processes.SortKey:
    return "memory" if value == "memory" else "cpu"


@router.get("/{machine_id}/processes")
async def machine_processes(
    request: Request,
    machine_id: uuid.UUID,
    sort: str = "cpu",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The top processes now, as the popover's body; it asks again every
    few seconds while it stays open."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    settings = await get_or_create_app_settings(db)
    include_args = current_user.has_permission(Permission.ACTION_TERMINAL)
    answer = await _wait(
        tasks.list_machine_processes.delay(
            str(machine.id), _sort(sort), processes.DEFAULT_LIMIT, include_args
        ),
        settings.ssh_connect_timeout + 15,
        request,
    )
    return templates.TemplateResponse(
        request,
        "partials/machine_processes.html",
        {
            "machine": machine,
            "sort": _sort(sort),
            "answer": answer,
            "show_args": include_args,
            "refresh_seconds": PROCESS_REFRESH_SECONDS,
        },
    )


@router.get("/{machine_id}/processes/{pid}")
async def machine_process_detail(
    request: Request,
    machine_id: uuid.UUID,
    pid: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if pid < 1:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    settings = await get_or_create_app_settings(db)
    include_args = current_user.has_permission(Permission.ACTION_TERMINAL)
    answer = await _wait(
        tasks.machine_process_detail.delay(str(machine.id), pid, include_args),
        settings.ssh_connect_timeout + 15,
        request,
    )
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/machine_process_detail.html",
        {
            "machine": machine,
            "pid": pid,
            "answer": answer,
            "process": answer.get("process"),
            "show_args": include_args,
            "can_signal": current_user.has_permission(Permission.ACTION_POWER),
            "csrf_token": csrf_token,
            "signal_result": None,
            "containers": {
                str(c.get("id") or "")[:12]: c.get("name")
                for c in machine.docker_containers or []
                if isinstance(c, dict)
            },
        },
    )


@router.post(
    "/{machine_id}/processes/{pid}/signal", dependencies=[need_power, Depends(verify_csrf)]
)
async def signal_machine_process(
    request: Request,
    machine_id: uuid.UUID,
    pid: int,
    start_ticks: int = Form(...),
    signal: str = Form("TERM"),
    name: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """TERM or KILL to one process — the one that was shown (its start
    time must still match). Audited either way."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if signal not in processes.SIGNALS or pid <= 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Bad signal or PID.")
    settings = await get_or_create_app_settings(db)
    answer = await _wait(
        tasks.signal_machine_process.delay(str(machine.id), pid, start_ticks, signal),
        settings.ssh_connect_timeout + 15,
        request,
    )
    outcome = str(answer.get("outcome") or "error")
    label = name.strip()[:64] or str(pid)
    await log_event(
        db,
        request=request,
        action="machine.process.signal",
        summary=f'Sent {signal} to process {pid} ("{label}") on "{machine.name}": {outcome}',
        outcome=AuditOutcome.SUCCESS if outcome == "ok" else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"pid": pid, "signal": signal, "process": label, "outcome": outcome,
                 **({"error": answer["error"]} if answer.get("error") else {})},
    )
    return templates.TemplateResponse(
        request,
        "partials/machine_process_signal.html",
        {"machine": machine, "pid": pid, "signal": signal, "outcome": outcome,
         "error": answer.get("error")},
    )


@router.post("/{machine_id}/connectivity-test", dependencies=[Depends(verify_csrf)])
async def test_machine_connectivity(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Gateway, internet target, DNS and the clock — checked from the
    machine now. Read-only, like the readings it repeats."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    settings = await get_or_create_app_settings(db)
    answer = await _wait(
        tasks.test_machine_connectivity.delay(str(machine.id)),
        settings.ssh_connect_timeout + 30,
        request,
    )
    return templates.TemplateResponse(
        request,
        "partials/machine_connectivity_test.html",
        {"machine": machine, "answer": answer, "live_settings": settings},
    )
