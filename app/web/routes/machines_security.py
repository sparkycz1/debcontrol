"""A machine's Security tab: its Lynis security audits
(`app.services.security_audit`) and "Run audit now"."""

from __future__ import annotations

import uuid

from fastapi import Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import security_audit
from app.services.machine_actions import trigger_security_audits
from app.web.flash import read_flash, sign_flash
from app.web.routes.machines_common import (
    _get_machine_or_404,
    _machine_tabs,
    machines_router,
    need_updates,
)
from app.web.templating import t, templates

router = machines_router()


@router.get("/{machine_id}/security")
async def machine_security(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The newest audit in full (hardening index, warnings, suggestions)
    and the index of the ones before it. While an audit is under way the
    panel re-fetches itself (an htmx request gets the panel alone)."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    audits = await security_audit.history(db, machine.id)
    current = audits[0] if audits else None
    shown = next((a for a in audits if a.hardening_index is not None), None)
    context = {
        "machine": machine,
        "audits": audits,
        "current": current,
        "shown": shown,
        "active": current is not None and security_audit.is_active(current),
        "display_status": security_audit.display_status,
        "control_url": security_audit.CONTROL_URL,
        "can_run": current_user.has_permission(Permission.ACTION_UPDATES),
        "audit_error": read_flash(request, "audit_error"),
    }
    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(request, "machines/_security_audit.html", context)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/security.html",
        {
            **context,
            "csrf_token": csrf_token,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "security",
        },
    )
    if new_cookie:
        set_csrf_cookie(response, csrf_token)
    return response


@router.post("/{machine_id}/security/audit", dependencies=[need_updates, Depends(verify_csrf)])
async def run_machine_security_audit(
    request: Request,
    machine_id: uuid.UUID,
    install: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Start a Lynis audit of this machine. Same permission as running
    updates: it runs a packaged tool as root and may install it."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    install_if_missing = install == "on"
    audits, _skipped = await trigger_security_audits(
        db, [machine], install_if_missing=install_if_missing, started_by=current_user.username
    )
    await log_event(
        db,
        request=request,
        action="machine.security_audit.run",
        summary=f'Started a security audit (Lynis) of "{machine.name}"'
        if audits
        else f'Could not start a security audit (Lynis) of "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if audits else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"install_if_missing": install_if_missing},
    )
    url = f"/machines/{machine.id}/security"
    if not audits:
        reason = (
            "security_audit.error.no_host_key"
            if not machine.host_key_fingerprint
            else "security_audit.error.already_running"
        )
        url += "?audit_error=" + sign_flash(t(request, reason))
    return RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)
