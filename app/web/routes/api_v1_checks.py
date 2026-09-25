"""REST API for TLS/HTTP endpoint checks — the same `EndpointCheckSave`
validation, permissions (`machine.view` to read, `machine.manage` to
change) and audit codes as the Checks page (`app/web/routes/checks.py`)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.endpoint_check import EndpointCheckSave
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
