"""REST API for TLS/HTTP endpoint checks — the same `EndpointCheckSave`
validation, permissions (`machine.view` to read, `machine.manage` to
change) and audit codes as the Checks page (`app/web/routes/checks.py`)."""

from __future__ import annotations

import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.core.app_settings import get_or_create_app_settings
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.acknowledgement import AcknowledgeRequest
from app.schemas.endpoint_check import EndpointCheckSave
from app.services import acknowledgements, monitoring_history
from app.services.access_scope import machines_visible_to
from app.services.endpoint_check_history import load_check_history
from app.services.endpoint_sla import load_sla_report
from app.tasks import jobs as tasks

router = APIRouter(prefix="/api/v1/checks")
_view = Depends(require_api_permission(Permission.MACHINE_VIEW))
_manage = Depends(require_api_permission(Permission.MACHINE_MANAGE))


def _to_dict(check: EndpointCheck) -> dict[str, Any]:
    def iso(value: Any) -> str | None:
        return value.isoformat() if value else None

    return {
        "id": str(check.id),
        "name": check.name,
        "kind": check.kind,
        "target": check.target,
        "expected_status": check.expected_status,
        "expected_body": check.expected_body,
        "unexpected_body": check.unexpected_body,
        "json_path": check.json_path,
        "json_expected": check.json_expected,
        "max_latency_ms": check.max_latency_ms,
        "sla_target_percent": check.sla_target_percent,
        "verify_tls": check.verify_tls,
        "interval_seconds": check.interval_seconds,
        "timeout_seconds": check.timeout_seconds,
        "cert_warn_days": check.cert_warn_days,
        "enabled": check.enabled,
        "last_checked_at": iso(check.last_checked_at),
        "last_ok": check.last_ok,
        "last_error": check.last_error,
        "last_status_code": check.last_status_code,
        "last_latency_ms": check.last_latency_ms,
        "cert_expires_at": iso(check.cert_expires_at),
        "acknowledgement": acknowledgements.as_dict(check),
    }


async def _get_or_404(check_id: uuid.UUID, db: AsyncSession) -> EndpointCheck:
    check = await db.get(EndpointCheck, check_id)
    if check is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return check


@router.get("", dependencies=[_view])
async def list_checks_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, Any]]:
    result = await db.execute(select(EndpointCheck).order_by(EndpointCheck.name))
    return [_to_dict(c) for c in result.scalars().all()]


@router.get("/sla", dependencies=[_view])
async def sla_report_api(
    db: AsyncSession = Depends(get_db),
    month: str = "",
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """The Checks → SLA report as data, for one calendar month in UTC
    (`month=YYYY-MM`, default the current one): per check probes, uptime %,
    estimated downtime, outage count and whether `sla_target_percent` was
    met — plus `machines`: every machine this token's user can see, with
    the same figures from its SSH reachability samples (`kind: "ssh"`,
    `check_id` = the machine's id)."""
    app_settings = await get_or_create_app_settings(db)
    machines = list((await db.execute(await machines_visible_to(db, user))).scalars().all())
    report = await load_sla_report(
        db,
        month,
        machines=[m for m in machines if m.is_active],
        reachability_interval_seconds=app_settings.reachability_check_interval_seconds,
    )
    return {
        "month": report.month,
        "start": report.start.isoformat(),
        "end": report.end.isoformat(),
        "checks": [row.as_dict() for row in report.rows],
        "machines": [row.as_dict() for row in report.machine_rows],
    }


@router.post("", dependencies=[_manage], status_code=status.HTTP_201_CREATED)
async def create_check_api(
    payload: EndpointCheckSave,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    check = EndpointCheck(**payload.model_dump())
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
    return _to_dict(check)


@router.put("/{check_id}", dependencies=[_manage])
async def update_check_api(
    check_id: uuid.UUID,
    payload: EndpointCheckSave,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    check = await _get_or_404(check_id, db)
    for field, value in payload.model_dump().items():
        setattr(check, field, value)
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
    return _to_dict(check)


@router.delete("/{check_id}", dependencies=[_manage], status_code=status.HTTP_204_NO_CONTENT)
async def delete_check_api(
    check_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> None:
    check = await _get_or_404(check_id, db)
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


@router.post("/{check_id}/run", dependencies=[_manage], status_code=status.HTTP_202_ACCEPTED)
async def run_check_api(
    check_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, str]:
    """Queue the check to run now; poll `GET /api/v1/checks` for the result."""
    check = await _get_or_404(check_id, db)
    tasks.run_endpoint_check.delay(str(check.id))
    await log_event(
        db,
        request=request,
        action="endpoint_check.run",
        summary=f'Ran check "{check.name}" now',
        target_type="endpoint_check",
        target_id=check.id,
        target_label=check.name,
    )
    return {"status": "queued"}


@router.get("/{check_id}/history", dependencies=[_view])
async def check_history_api(
    check_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    start: datetime | None = None,
    end: datetime | None = None,
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """A check's detail page as data: uptime %, average/p95 latency,
    downsampled uptime and latency series over `range_key` (`1h`/`24h`/
    `7d`/`30d`/`90d`, sharing `bucket_timestamps` as the X axis) and the
    latest failures. `start` + `end` (ISO 8601, UTC when no offset is
    given) ask for a custom window instead."""
    check = await _get_or_404(check_id, db)

    def utc(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)

    window = monitoring_history.resolve_window(range_key, utc(start), utc(end))
    history = await load_check_history(db, check.id, window)
    encoded: dict[str, Any] = jsonable_encoder(asdict(history))
    return encoded


@router.post("/{check_id}/acknowledge", dependencies=[_manage])
async def acknowledge_check_api(
    payload: AcknowledgeRequest,
    request: Request,
    check_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Acknowledge a problem on a check — see
    `app.services.acknowledgements`."""
    check = await _get_or_404(check_id, db)
    acknowledgements.acknowledge(check, by=user.username, note=payload.note, hours=payload.hours)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="endpoint_check.acknowledge",
        summary=f'Acknowledged a problem on check "{check.name}" (REST API)',
        target_type="endpoint_check",
        target_id=check.id,
        target_label=check.name,
        details={"hours": payload.hours, "note": check.acknowledged_note},
    )
    return {"acknowledgement": acknowledgements.as_dict(check)}


@router.delete(
    "/{check_id}/acknowledge", dependencies=[_manage], status_code=status.HTTP_204_NO_CONTENT
)
async def clear_check_acknowledgement_api(
    request: Request, check_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    check = await _get_or_404(check_id, db)
    acknowledgements.clear(check)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="endpoint_check.acknowledge.clear",
        summary=f'Cleared the acknowledgement on check "{check.name}" (REST API)',
        target_type="endpoint_check",
        target_id=check.id,
        target_label=check.name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
