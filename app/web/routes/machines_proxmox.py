"""One Proxmox VE guest (`/machines/{id}/proxmox/guests/{vmid}`): its page,
its notes and its console. The guest list, guest power actions and the
backup sign-off stay with the Proxmox tab in `machines_detail`.

- the page (`machine.view`): state, CPU, memory and I/O rates (monitoring
  sample), IP addresses, notes, disks, mount points and network cards
  (facts refresh, `Machine.pve_guest_details`), and the managed machine it
  is, if any;
- notes (`machine.manage`, audited as `machine.guest.notes`): written to
  the guest's `description` with `pvesh set`, the same notes the Proxmox
  web UI shows;
- console (`action.terminal`): the machine terminal's WebSocket with
  `?guest=<vmid>` — `pct enter` for a container, `qm terminal` for a VM's
  serial console — with the same time limit, recording and audit as the
  terminal (`machine.guest.console.open` / `.close`).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import proxmox_guest_links
from app.ssh import proxmox
from app.tasks import jobs as tasks
from app.web.flash import sign_flash
from app.web.messages import LocalizedText
from app.web.routes.machines_common import (
    _get_machine_or_404,
    _machine_tabs,
    machines_router,
    need_manage,
)
from app.web.templating import t, templates

router = machines_router()
need_terminal = Depends(require_permission(Permission.ACTION_TERMINAL))


def guest_or_404(machine: Machine, vmid: int) -> dict[str, Any]:
    guest = proxmox.find_guest(machine.pve_guests, vmid)
    if guest is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such guest.")
    return guest


def guest_details(machine: Machine, vmid: int) -> dict[str, Any] | None:
    details = (machine.pve_guest_details or {}).get(str(vmid))
    return details if isinstance(details, dict) else None


def is_local(machine: Machine, guest: dict[str, Any]) -> bool:
    """Whether the guest runs on this very node (its console can only be
    opened there)."""
    node = proxmox.local_node(machine.pve_cluster, machine.pve_resources)
    return node is None or not guest.get("node") or guest.get("node") == node


@router.get("/{machine_id}/proxmox/guests/{vmid}")
async def proxmox_guest_page(
    request: Request,
    machine_id: uuid.UUID,
    vmid: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    guest = guest_or_404(machine, vmid)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    paired = await proxmox_guest_links.machines_for_guests(db, current_user, machine)
    response = templates.TemplateResponse(
        request,
        "machines/proxmox_guest.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "proxmox",
            "csrf_token": csrf_token,
            "guest": guest,
            "details": guest_details(machine, vmid),
            "managed": paired.get(vmid),
            "local": is_local(machine, guest),
            "can_manage": current_user.has_permission(Permission.MACHINE_MANAGE),
            "can_terminal": current_user.has_permission(Permission.ACTION_TERMINAL),
            "can_power": current_user.has_permission(Permission.ACTION_POWER),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


async def set_notes(
    request: Request, db: AsyncSession, machine: Machine, guest: dict[str, Any], notes: str
) -> str | None:
    """Write the notes (through the worker) and audit it; the error, or
    None. Shared with the REST API."""
    app_settings = await get_or_create_app_settings(db)
    vmid = int(guest["vmid"])
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            tasks.set_proxmox_guest_notes.delay(str(machine.id), vmid, notes).get,
            timeout=app_settings.ssh_connect_timeout + 90,
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = str(LocalizedText(request, "common.error.command_timeout"))
    except Exception as exc:
        error = str(exc)
    label = f"{vmid} ({guest.get('name')})" if guest.get("name") else str(vmid)
    await log_event(
        db,
        request=request,
        action="machine.guest.notes",
        summary=f'Notes of guest {label} changed on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"vmid": vmid, "length": len(notes), **({"error": error} if error else {})},
    )
    return error


@router.post(
    "/{machine_id}/proxmox/guests/{vmid}/notes",
    dependencies=[need_manage, Depends(verify_csrf)],
)
async def proxmox_guest_notes(
    request: Request,
    machine_id: uuid.UUID,
    vmid: int,
    notes: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    guest = guest_or_404(machine, vmid)
    error = await set_notes(request, db, machine, guest, notes)
    query = (
        f"guest_error={sign_flash(error)}"
        if error
        else f"guest_notice={sign_flash(t(request, 'proxmox.guest.notes_saved'))}"
    )
    return RedirectResponse(
        url=f"/machines/{machine.id}/proxmox/guests/{vmid}?{query}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/{machine_id}/proxmox/guests/{vmid}/console", dependencies=[need_terminal])
async def proxmox_guest_console(
    request: Request,
    machine_id: uuid.UUID,
    vmid: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    guest = guest_or_404(machine, vmid)
    if guest.get("template") or not is_local(machine, guest):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Not a guest of this node."
        )
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before opening a terminal.",
        )
    return templates.TemplateResponse(
        request,
        "machines/proxmox_console.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "proxmox",
            "guest": guest,
            "ws_path": f"/machines/{machine.id}/terminal/ws?guest={vmid}",
            "recording": (await get_or_create_app_settings(db)).terminal_recording_enabled,
        },
    )
