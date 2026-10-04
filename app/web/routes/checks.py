"""The Checks page — TLS certificate and HTTP endpoint checks run from the
debcontrol server (see `app.services.endpoint_checks`). Viewing needs
`machine.view`; creating, editing, deleting and "Run now" need
`machine.manage`."""

from __future__ import annotations

import asyncio
import uuid

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse, RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.endpoint_check import EndpointCheckSave
from app.services import acknowledgements, monitoring_history
from app.services.access_scope import machines_visible_to
from app.services.endpoint_check_history import load_check_history
from app.services.endpoint_sla import (
    SlaReport,
    load_sla_report,
    selectable_months,
    sla_report_csv,
)
from app.tasks import jobs as tasks
from app.web.templating import t, templates

router = APIRouter(
    prefix="/checks", dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))]
)
_manage = Depends(require_permission(Permission.MACHINE_MANAGE))


def _form_error(exc: ValidationError) -> str:
    first = exc.errors()[0]
    field = ".".join(str(part) for part in first.get("loc", ()) if part != "__root__")
    message = str(first.get("msg", "Invalid value.")).removeprefix("Value error, ")
    return f"{field}: {message}" if field else message


async def _parse_form(request: Request) -> tuple[EndpointCheckSave | None, dict[str, str], str]:
    form = await request.form()
    values = {key: str(form.get(key, "")) for key in (
        "name", "kind", "target", "expected_status", "expected_body", "unexpected_body",
        "json_path", "json_expected", "max_latency_ms", "sla_target_percent",
        "interval_seconds", "timeout_seconds", "cert_warn_days",
    )}
    values["verify_tls"] = "1" if form.get("verify_tls") else ""
    values["enabled"] = "1" if form.get("enabled") else ""
    try:
        payload = EndpointCheckSave(
            name=values["name"],
            kind=values["kind"],
            target=values["target"],
            expected_status=int(values["expected_status"]) if values["expected_status"] else None,
            expected_body=values["expected_body"] or None,
            unexpected_body=values["unexpected_body"] or None,
            json_path=values["json_path"] or None,
            json_expected=values["json_expected"] or None,
            max_latency_ms=int(values["max_latency_ms"]) if values["max_latency_ms"] else None,
            sla_target_percent=(
                float(values["sla_target_percent"].replace(",", "."))
                if values["sla_target_percent"]
                else None
            ),
            verify_tls=bool(values["verify_tls"]),
            interval_seconds=int(values["interval_seconds"] or 300),
            timeout_seconds=int(values["timeout_seconds"] or 10),
            cert_warn_days=int(values["cert_warn_days"] or 14),
            enabled=bool(values["enabled"]),
        )
    except ValidationError as exc:
        return None, values, _form_error(exc)
    except ValueError:
        return None, values, t(request, "checks.error.numbers_only")
    return payload, values, ""


def _apply(check: EndpointCheck, payload: EndpointCheckSave) -> None:
    for field, value in payload.model_dump().items():
        setattr(check, field, value)


async def _get_check_or_404(check_id: uuid.UUID, db: AsyncSession) -> EndpointCheck:
    check = await db.get(EndpointCheck, check_id)
    if check is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return check


def _render_form(
    request: Request, check: EndpointCheck | None, values: dict[str, str], error: str
) -> Response:
    return templates.TemplateResponse(
        request,
        "checks/form.html",
        {"check": check, "values": values, "error": error},
        status_code=status.HTTP_400_BAD_REQUEST if error else status.HTTP_200_OK,
    )


def _values_of(check: EndpointCheck) -> dict[str, str]:
    return {
        "name": check.name,
        "kind": check.kind,
        "target": check.target,
        "expected_status": str(check.expected_status or ""),
        "expected_body": check.expected_body or "",
        "unexpected_body": check.unexpected_body or "",
        "json_path": check.json_path or "",
        "json_expected": check.json_expected or "",
        "max_latency_ms": str(check.max_latency_ms or ""),
        "sla_target_percent": _format_percent(check.sla_target_percent),
        "interval_seconds": str(check.interval_seconds),
        "timeout_seconds": str(check.timeout_seconds),
        "cert_warn_days": str(check.cert_warn_days),
        "verify_tls": "1" if check.verify_tls else "",
        "enabled": "1" if check.enabled else "",
    }


def _format_percent(value: float | None) -> str:
    return "" if value is None else f"{value:g}"


_DEFAULT_VALUES = {
    "name": "", "kind": "http", "target": "", "expected_status": "", "expected_body": "",
    "unexpected_body": "", "json_path": "", "json_expected": "", "max_latency_ms": "",
    "sla_target_percent": "",
    "interval_seconds": "300", "timeout_seconds": "10", "cert_warn_days": "14",
    "verify_tls": "1", "enabled": "1",
}


@router.get("")
async def list_checks(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(select(EndpointCheck).order_by(EndpointCheck.name))
    return templates.TemplateResponse(
        request,
        "checks/list.html",
        {
            "checks": list(result.scalars().all()),
            "run_error": request.query_params.get("run_error"),
            "ran": request.query_params.get("ran"),
        },
    )


async def _sla_report(db: AsyncSession, month: str, user: User) -> SlaReport:
    """The SLA report with the machines this user can see."""
    app_settings = await get_or_create_app_settings(db)
    machines = list((await db.execute(await machines_visible_to(db, user))).scalars().all())
    return await load_sla_report(
        db,
        month,
        machines=[m for m in machines if m.is_active],
        reachability_interval_seconds=app_settings.reachability_check_interval_seconds,
    )


@router.get("/sla")
async def sla_report(
    request: Request,
    db: AsyncSession = Depends(get_db),
    month: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """Monthly availability per check against its SLA target — see
    `app.services.endpoint_sla`."""
    report = await _sla_report(db, month, current_user)
    return templates.TemplateResponse(
        request,
        "checks/sla.html",
        {"report": report, "months": selectable_months()},
    )


@router.get("/sla.csv")
async def sla_report_export(
    db: AsyncSession = Depends(get_db),
    month: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    report = await _sla_report(db, month, current_user)
    return PlainTextResponse(
        sla_report_csv(report),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="debcontrol-sla-{report.month}.csv"'
        },
    )


@router.get("/new", dependencies=[_manage])
async def new_check_form(request: Request) -> Response:
    return _render_form(request, None, dict(_DEFAULT_VALUES), "")


@router.post("/new", dependencies=[_manage, Depends(verify_csrf)])
async def create_check(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    payload, values, error = await _parse_form(request)
    if payload is None:
        return _render_form(request, None, values, error)
    check = EndpointCheck()
    _apply(check, payload)
    db.add(check)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="endpoint_check.create",
        summary=f'Created {check.kind.upper()} check "{check.name}" ({check.target})',
        target_type="endpoint_check",
        target_id=check.id,
        target_label=check.name,
    )
    tasks.run_endpoint_check.delay(str(check.id))
    return RedirectResponse(url="/checks", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{check_id}/edit", dependencies=[_manage])
async def edit_check_form(
    request: Request, check_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    check = await _get_check_or_404(check_id, db)
    return _render_form(request, check, _values_of(check), "")


@router.post("/{check_id}/edit", dependencies=[_manage, Depends(verify_csrf)])
async def update_check(
    request: Request, check_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    check = await _get_check_or_404(check_id, db)
    payload, values, error = await _parse_form(request)
    if payload is None:
        return _render_form(request, check, values, error)
    _apply(check, payload)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="endpoint_check.update",
        summary=f'Updated check "{check.name}" ({check.target})',
        target_type="endpoint_check",
        target_id=check.id,
        target_label=check.name,
    )
    return RedirectResponse(url="/checks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{check_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_check(
    request: Request, check_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    check = await _get_check_or_404(check_id, db)
    name, target = check.name, check.target
    await db.delete(check)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="endpoint_check.delete",
        summary=f'Deleted check "{name}" ({target})',
        target_type="endpoint_check",
        target_id=check_id,
        target_label=name,
    )
    return RedirectResponse(url="/checks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{check_id}/run", dependencies=[_manage, Depends(verify_csrf)])
async def run_check_now(
    request: Request, check_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    check = await _get_check_or_404(check_id, db)
    error: str | None = None
    try:
        async_result = tasks.run_endpoint_check.delay(str(check.id))
        await asyncio.to_thread(async_result.get, timeout=check.timeout_seconds * 2 + 20)
    except CeleryTimeoutError:
        error = "The check did not finish in time."
    except Exception as exc:
        error = str(exc)
    await log_event(
        db,
        request=request,
        action="endpoint_check.run",
        summary=f'Ran check "{check.name}" now',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="endpoint_check",
        target_id=check.id,
        target_label=check.name,
        details={"error": error} if error else None,
    )
    url = f"/checks?ran={check.id}" if error is None else "/checks?run_error=1"
    return RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{check_id}")
async def check_detail(
    request: Request,
    check_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
) -> Response:
    """One check's history: uptime %, latency, uptime/latency charts over
    the chosen range (same selector as a machine's Monitoring tab) and its
    most recent failures — see `app.services.endpoint_check_history`."""
    check = await _get_check_or_404(check_id, db)
    range_key = monitoring_history.normalize_range_key(range_key)
    history = await load_check_history(db, check.id, range_key)
    return templates.TemplateResponse(
        request,
        "checks/detail.html",
        {
            "check": check,
            "history": history,
            "range_key": range_key,
            "time_ranges": monitoring_history.TIME_RANGES,
        },
    )


# --- Acknowledging a problem (app.services.acknowledgements) ---------------


@router.post("/{check_id}/acknowledge", dependencies=[_manage, Depends(verify_csrf)])
async def acknowledge_check(
    request: Request,
    check_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    duration: str = Form("until_recovered"),
    note: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    check = await _get_check_or_404(check_id, db)
    try:
        hours = acknowledgements.hours_for(duration)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from None
    acknowledgements.acknowledge(check, by=current_user.username, note=note, hours=hours)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="endpoint_check.acknowledge",
        summary=f'Acknowledged a problem on check "{check.name}"',
        target_type="endpoint_check",
        target_id=check.id,
        target_label=check.name,
        details={"hours": hours, "note": check.acknowledged_note},
    )
    return RedirectResponse(url=f"/checks/{check.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{check_id}/acknowledge/clear", dependencies=[_manage, Depends(verify_csrf)])
async def clear_check_acknowledgement(
    request: Request, check_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    check = await _get_check_or_404(check_id, db)
    acknowledgements.clear(check)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="endpoint_check.acknowledge.clear",
        summary=f'Cleared the acknowledgement on check "{check.name}"',
        target_type="endpoint_check",
        target_id=check.id,
        target_label=check.name,
    )
    return RedirectResponse(url=f"/checks/{check.id}", status_code=status.HTTP_303_SEE_OTHER)
