"""Self-registration endpoint: a machine announces itself for review.

This is a machine-to-machine JSON API, not a browser form — there's no
cookie involved, so CSRF protection doesn't apply here (CSRF exploits a
browser automatically attaching cookies to a cross-site request; nothing
here relies on cookies). Two kinds of bearer token are accepted:

- The shared `INFORM_TOKEN` from the environment — the original mechanism,
  kept for backward compatibility with anything already provisioned with it.
- A per-user API token (`app.auth.api_tokens`) belonging to a user whose
  role has `machine.manage` — lets self-registration be attributed to
  (and revoked for) a specific person/script instead of one token shared
  by every machine.

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
from app.auth.api_tokens import get_valid_api_token
from app.core.config import get_settings
from app.db.models.audit_log import AuditOutcome
from app.db.models.pending_machine import PendingMachine
from app.db.models.role import Permission
from app.db.session import get_db
from app.schemas.inform import InformPayload

router = APIRouter(prefix="/api")


async def _verify_inform_token(request: Request, db: AsyncSession = Depends(get_db)) -> None:
    provided = request.headers.get("Authorization", "")
    expected = f"Bearer {get_settings().inform_token.get_secret_value()}"
    if secrets.compare_digest(provided, expected):
        return

    if provided.startswith("Bearer "):
        token = await get_valid_api_token(db, provided.removeprefix("Bearer ").strip())
        # A read-only token can't add a machine, and a group-limited one
        # can't either: a new machine has no group yet.
        if (
            token is not None
            and not token.read_only
            and token.machine_group_ids is None
            and token.user.has_permission(Permission.MACHINE_MANAGE)
        ):
            return

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
        summary=f"Machine self-registered as pending ({pending.ip_address})",
        target_type="pending_machine",
        target_id=pending.id,
        target_label=pending.ip_address,
    )

    return {"status": "received"}
