"""Self-registration endpoint: a machine announces itself for review.

This is a machine-to-machine JSON API authenticated with a shared bearer
token (`INFORM_TOKEN`), not a browser form — there's no cookie involved, so
CSRF protection doesn't apply here (CSRF exploits a browser automatically
attaching cookies to a cross-site request; nothing here relies on cookies).

Nothing submitted here is trusted for connecting to the machine — it just
creates a `PendingMachine` row for a human to review. Turning it into a
real, manageable `Machine` still goes through the normal add-machine form
and the mandatory host-key discovery/confirmation flow.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.core.config import get_settings
from app.db.models.audit_log import AuditOutcome
from app.db.models.pending_machine import PendingMachine
from app.db.session import get_db
from app.schemas.inform import InformPayload

router = APIRouter(prefix="/api")


async def _verify_inform_token(request: Request, db: AsyncSession = Depends(get_db)) -> None:
    expected = f"Bearer {get_settings().inform_token.get_secret_value()}"
    provided = request.headers.get("Authorization", "")
    if not secrets.compare_digest(provided, expected):
        await log_event(
            db,
            request=request,
            action="machine.self_register",
            summary="Blocked self-registration: invalid or missing bearer token",
            outcome=AuditOutcome.DENIED,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing bearer token."
        )


@router.post(
    "/inform",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_verify_inform_token)],
)
async def inform(
    request: Request, payload: InformPayload, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    source_ip = request.client.host if request.client else None
    pending = PendingMachine(
        ip_address=payload.ip_address or source_ip or "unknown",
        reported_hostname=payload.hostname,
        os_version=payload.os_version,
        kernel_version=payload.kernel_version,
        cpu_cores=payload.cpu_cores,
        ram_bytes=payload.ram_bytes,
        disks=payload.disks,
        source_ip=source_ip,
    )
    db.add(pending)
    await db.commit()
    await db.refresh(pending)

    await log_event(
        db,
        request=request,
        action="machine.self_register",
        summary=f'Machine self-registered as pending ({pending.ip_address})',
        target_type="pending_machine",
        target_id=pending.id,
        target_label=pending.ip_address,
    )

    return {"status": "received"}
