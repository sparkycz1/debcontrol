"""Settings — the app's SSH identity, background-check intervals (both
read-only, sourced from the environment), and the audit log retention
policy (the first setting actually editable through the UI — see
`app/db/models/app_settings.py` for why that's a separate mechanism from
`app.core.config.Settings`). No user accounts to configure yet (no auth).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event, verify_chain
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.session import get_db
from app.ssh.identity import get_or_create_identity
from app.web.templating import templates

router = APIRouter(prefix="/settings")


async def _render_settings(
    request: Request, db: AsyncSession, errors: list[str], **extra: object
) -> Response:
    identity = await get_or_create_identity(db)
    app_settings = await get_or_create_app_settings(db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    context: dict[str, object] = {
        "identity": identity,
        "settings": get_settings(),
        "app_settings": app_settings,
        "csrf_token": csrf_token,
        "errors": errors,
        **extra,
    }
    response = templates.TemplateResponse(request, "settings/index.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("")
async def show_settings(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    return await _render_settings(request, db, [])


@router.post("/audit-retention", dependencies=[Depends(verify_csrf)])
async def update_audit_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    raw = retention_days.strip()

    if raw == "":
        new_value = None
    else:
        try:
            new_value = int(raw)
            if new_value < 0:
                raise ValueError("must not be negative")
        except ValueError:
            return await _render_settings(
                request, db, [f'"{raw}" isn\'t a whole number of days (0 or more).']
            )

    app_settings.audit_log_retention_days = new_value
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.audit_retention.update",
        summary=(
            f"Set audit log retention to {new_value} day(s)"
            if new_value is not None
            else "Set audit log retention to keep forever"
        ),
    )

    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/audit-verify", dependencies=[Depends(verify_csrf)])
async def verify_audit_chain(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    """Recompute the audit log's hash chain on demand — see
    `app.audit.verify_chain`. Result isn't stored anywhere; it's only ever
    the answer to "is the trail intact right now."""
    result = await verify_chain(db)
    await log_event(
        db,
        request=request,
        action="audit_log.verify",
        summary=f"Verified audit log hash chain: {result.message}",
        outcome=AuditOutcome.SUCCESS if result.ok else AuditOutcome.FAILURE,
        details={"checked": result.checked, "broken_at_sequence": result.broken_at_sequence},
    )
    return await _render_settings(request, db, [], verify_result=result)
