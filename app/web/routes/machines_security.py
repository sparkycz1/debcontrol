"""A machine's Security tab: its security audits — Lynis and debcontrol's
own checks (`app.services.security_audit`) — "Run audit now", and marking
a finding OK on this machine (or taking that back)."""

from __future__ import annotations

import uuid

from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.role import Permission
from app.db.models.security_audit import SecurityAuditStatus
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
    shown = next((a for a in audits if a.status == SecurityAuditStatus.SUCCEEDED), None)
    marked = await security_audit.suppressions(db, machine.id)
    suppressed = set(marked)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    context = {
        "machine": machine,
        "audits": audits,
        "current": current,
        "shown": shown,
        "view": security_audit.annotate(shown, suppressed) if shown else None,
        "marked": marked,
        "counts_of": lambda a: security_audit.counts(a, suppressed),
        "active": current is not None and security_audit.is_active(current),
        "display_status": security_audit.display_status,
        "control_url": security_audit.CONTROL_URL,
        "can_run": current_user.has_permission(Permission.ACTION_UPDATES),
        "audit_error": read_flash(request, "audit_error"),
        "csrf_token": csrf_token,
    }
    if request.headers.get("HX-Request") == "true":
        response = templates.TemplateResponse(request, "machines/_security_audit.html", context)
    else:
        response = templates.TemplateResponse(
            request,
            "machines/security.html",
            {
                **context,
                "tabs": _machine_tabs(request, machine, current_user),
                "active_tab": "security",
            },
        )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
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


@router.post("/{machine_id}/security/ok", dependencies=[need_updates, Depends(verify_csrf)])
async def mark_security_finding_ok(
    request: Request,
    machine_id: uuid.UUID,
    key: str = Form(...),
    label: str = Form(""),
    note: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Mark one finding OK on this machine: it is listed apart and no
    longer counts, on this audit and every later one."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not security_audit.valid_key(key):
        raise HTTPException(status_code=400, detail="Unknown finding.")
    added = await security_audit.suppress(
        db, machine.id, key, label=label, note=note, created_by=current_user.username
    )
    await db.commit()
    if added:
        await log_event(
            db,
            request=request,
            action="machine.security_audit.mark_ok",
            summary=f'Marked a security audit finding OK on "{machine.name}": {label[:200]}',
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
            details={"key": key, "label": label[:500], "note": note[:500] or None},
        )
    return RedirectResponse(
        url=f"/machines/{machine.id}/security#marked-ok", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post(
    "/{machine_id}/security/ok/remove", dependencies=[need_updates, Depends(verify_csrf)]
)
async def unmark_security_finding_ok(
    request: Request,
    machine_id: uuid.UUID,
    key: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Take an "OK" back: the finding counts again."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    marked = await security_audit.suppressions(db, machine.id)
    row = marked.get(key)
    removed = await security_audit.unsuppress(db, machine.id, key)
    await db.commit()
    if removed:
        await log_event(
            db,
            request=request,
            action="machine.security_audit.unmark_ok",
            summary=f'Security audit finding counts again on "{machine.name}": '
            f"{(row.label if row else key)[:200]}",
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
            details={"key": key},
        )
    return RedirectResponse(
        url=f"/machines/{machine.id}/security", status_code=status.HTTP_303_SEE_OTHER
    )
