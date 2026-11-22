"""REST API for a machine's live view — the same reads and the same signal
as the Overview's live cards, the top processes popover and "Test
connectivity" (`app.web.routes.machines_live`), under the same
permissions and audit action code, scoped to the machines the token's
account can see.

- `GET /api/v1/machines/{id}/live` — the Overview's cards (CPU, memory,
  storage, network, temperature) from the newest monitoring samples.
- `GET /api/v1/machines/{id}/network` — every interface (kind, state,
  speed, bridge/bond, addresses, current rates, errors and drops) and the
  newest connectivity reading. No SSH.
- `GET /api/v1/machines/{id}/processes?sort=cpu|memory&limit=` — the top
  processes now (read over SSH). Command lines only with
  `action.terminal`, as in the web UI: they can hold passwords.
- `GET /api/v1/machines/{id}/processes/{pid}` — one process's detail.
- `POST /api/v1/machines/{id}/processes/{pid}/signal` — `TERM` or `KILL`,
  with the `start_ticks` the detail returned, so a PID that was reused in
  the meantime is left alone. `action.power`; audited as
  `machine.process.signal`.
- `POST /api/v1/machines/{id}/connectivity-test` — gateway, internet
  target, DNS and the clock, checked from the machine now. `machine.view`.

Rates are bytes per second here whatever the account shows (the unit
choice is only about display). The SSH reads run on a worker (`app.tasks.
jobs`), so the reused connection is used; a machine that can't be reached
answers 502, a worker that never answered 504."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import asdict
from typing import Any

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.core.app_settings import get_or_create_app_settings
from app.db.models.audit_log import AuditOutcome
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import live_overview
from app.ssh import processes
from app.tasks import jobs as tasks
from app.web.routes.api_v1 import _get_machine_or_404

router = APIRouter(prefix="/api/v1")

_view = Depends(require_api_permission(Permission.MACHINE_VIEW))
_power = Depends(require_api_permission(Permission.ACTION_POWER))


async def _wait(result: Any, wait_seconds: int) -> dict[str, Any]:
    """The worker's answer; 504 when none came, 502 when the machine
    couldn't be read."""
    try:
        value = await asyncio.to_thread(result.get, timeout=wait_seconds)
    except CeleryTimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail="The worker did not answer."
        ) from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Unexpected answer.")
    return value


def _failed(answer: dict[str, Any]) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY, detail=str(answer.get("error") or "Failed.")
    )


@router.get("/machines/{machine_id}/live", dependencies=[_view])
async def machine_live_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    samples = await live_overview.load_recent(db, machine.id)
    cards = asdict(live_overview.build_cards(machine, samples))
    cards["sampled_at"] = cards["sampled_at"].isoformat() if cards["sampled_at"] else None
    return cards


@router.get("/machines/{machine_id}/network", dependencies=[_view])
async def machine_network_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    samples = await live_overview.load_recent(db, machine.id)
    newest = samples[0] if samples else None
    previous = samples[1] if len(samples) > 1 else None
    return {
        "sampled_at": newest.sampled_at.isoformat() if newest else None,
        "default_gateway": machine.default_gateway,
        "interfaces": live_overview.interface_table(machine, newest, previous),
        "connectivity": {
            "gateway_latency_ms": newest.gateway_latency_ms,
            "gateway_loss_percent": newest.gateway_loss_percent,
            "internet_latency_ms": newest.internet_latency_ms,
            "internet_loss_percent": newest.internet_loss_percent,
            "dns_ok": newest.dns_ok,
            "dns_ms": newest.dns_ms,
            "ntp_synced": newest.ntp_synced,
            "ntp_offset_ms": newest.ntp_offset_ms,
        }
        if newest
        else None,
    }


@router.get("/machines/{machine_id}/processes", dependencies=[_view])
async def machine_processes_api(
    machine_id: uuid.UUID,
    sort: str = Query("cpu", pattern="^(cpu|memory)$"),
    limit: int = Query(processes.DEFAULT_LIMIT, ge=1, le=processes.MAX_LIMIT),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    settings = await get_or_create_app_settings(db)
    include_args = user.has_permission(Permission.ACTION_TERMINAL)
    answer = await _wait(
        tasks.list_machine_processes.delay(
            str(machine.id), "memory" if sort == "memory" else "cpu", limit, include_args
        ),
        settings.ssh_connect_timeout + 15,
    )
    if not answer.get("ok"):
        raise _failed(answer)
    answer.pop("ok", None)
    return answer


@router.get("/machines/{machine_id}/processes/{pid}", dependencies=[_view])
async def machine_process_detail_api(
    machine_id: uuid.UUID,
    pid: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    if pid < 1:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    settings = await get_or_create_app_settings(db)
    answer = await _wait(
        tasks.machine_process_detail.delay(
            str(machine.id), pid, user.has_permission(Permission.ACTION_TERMINAL)
        ),
        settings.ssh_connect_timeout + 15,
    )
    if not answer.get("ok"):
        raise _failed(answer)
    process = answer.get("process")
    if not process:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such process.")
    return dict(process)


class _SignalRequest(BaseModel):
    signal: str = Field("TERM", pattern="^(TERM|KILL)$")
    start_ticks: int = Field(ge=0)


@router.post("/machines/{machine_id}/processes/{pid}/signal", dependencies=[_power])
async def signal_machine_process_api(
    request: Request,
    machine_id: uuid.UUID,
    pid: int,
    payload: _SignalRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """`outcome` is `ok`, `gone` (the process ended, or the PID now
    belongs to another one), `denied` or `error`. Audited either way."""
    machine = await _get_machine_or_404(machine_id, db, user)
    if pid <= 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Bad PID.")
    settings = await get_or_create_app_settings(db)
    answer = await _wait(
        tasks.signal_machine_process.delay(
            str(machine.id), pid, payload.start_ticks, payload.signal
        ),
        settings.ssh_connect_timeout + 15,
    )
    outcome = str(answer.get("outcome") or "error")
    await log_event(
        db,
        request=request,
        action="machine.process.signal",
        summary=f'Sent {payload.signal} to process {pid} on "{machine.name}": {outcome}',
        outcome=AuditOutcome.SUCCESS if outcome == "ok" else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"pid": pid, "signal": payload.signal, "outcome": outcome,
                 **({"error": answer["error"]} if answer.get("error") else {})},
    )
    return {"pid": pid, "signal": payload.signal, "outcome": outcome,
            "error": answer.get("error")}


@router.post("/machines/{machine_id}/connectivity-test", dependencies=[_view])
async def test_machine_connectivity_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    settings = await get_or_create_app_settings(db)
    answer = await _wait(
        tasks.test_machine_connectivity.delay(str(machine.id)),
        settings.ssh_connect_timeout + 30,
    )
    if not answer.get("ok"):
        raise _failed(answer)
    answer.pop("ok", None)
    return answer
