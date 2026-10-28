"""REST API for Security → Container vulnerabilities: the critical and high
vulnerabilities across the visible machines' Docker images, where each
one is, and accepting one until a date (`app.services.docker_acceptances`).

The same permissions as the web pages: `machine.view` to read (scoped to
the machines the token's account can see), `action.updates` to accept or
revoke — and, since an acceptance applies to every machine, only for an
account not limited to some machine groups (403 otherwise).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.docker import DockerVulnerabilityAcceptance
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_acceptances
from app.services.access_scope import is_restricted, machines_visible_to
from app.tasks.docker_jobs import recompute_vulnerability_acceptances

router = APIRouter(prefix="/api/v1/docker", tags=["docker"])
_view = Depends(require_api_permission(Permission.MACHINE_VIEW))
_updates = Depends(require_api_permission(Permission.ACTION_UPDATES))


def _acceptance(row: DockerVulnerabilityAcceptance) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "vuln_id": row.vuln_id,
        # "" = every image, else an image repository ("docker.io/library/nginx").
        "image": row.image,
        "reason": row.reason,
        "expires_at": row.expires_at.isoformat(),
        "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


async def _visible_ids(db: AsyncSession, user: User) -> Any:
    return (await machines_visible_to(db, user)).with_only_columns(Machine.id)


async def _require_unrestricted(db: AsyncSession, user: User) -> None:
    if await is_restricted(db, user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accepting a vulnerability applies to every machine; "
            "an account limited to some machine groups can't.",
        )


@router.get("/vulnerabilities", dependencies=[_view])
async def fleet_vulnerabilities_api(
    q: str = "",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Every critical and high vulnerability in the latest image scans of
    the visible machines, most severe and widespread first (at most 500;
    `truncated` when there were more — narrow with `q`, a CVE or package)."""
    rows, truncated = await docker_acceptances.fleet_overview(
        db, await _visible_ids(db, user), query=q
    )
    return {
        "truncated": truncated,
        "vulnerabilities": [
            {
                "vuln_id": r.vuln_id,
                "severity": r.severity,
                "machines": r.machines,
                "images": r.images,
                "fixable": r.fixable,
                "accepted": r.accepted,
            }
            for r in rows
        ],
    }


@router.get("/vulnerabilities/{vuln_id}", dependencies=[_view])
async def fleet_vulnerability_api(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Where one vulnerability is (machine, image, package, versions) and
    its acceptances."""
    if not docker_acceptances.is_vuln_id_valid(vuln_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    found = await docker_acceptances.occurrences(db, vuln_id, await _visible_ids(db, user))
    acceptances = [a for a in await docker_acceptances.active(db) if a.vuln_id == vuln_id]
    if not found and await is_restricted(db, user):
        acceptances = []
    return {
        "vuln_id": vuln_id,
        "occurrences": [
            {
                "machine_id": str(o.machine.id),
                "machine_name": o.machine.name,
                "image": o.image_ref,
                "image_id": o.image_id,
                "severity": o.severity,
                "pkg": o.pkg,
                "installed": o.installed,
                "fixed": o.fixed,
            }
            for o in found
        ],
        "acceptances": [_acceptance(a) for a in acceptances],
    }


@router.get("/vulnerability-acceptances", dependencies=[_view])
async def acceptances_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, Any]]:
    """Every acceptance still in force (empty for an account limited to
    some machine groups — they are fleet-wide)."""
    if await is_restricted(db, user):
        return []
    return [_acceptance(a) for a in await docker_acceptances.active(db)]


class _AcceptRequest(BaseModel):
    vuln_id: str = Field(min_length=1, max_length=128)
    # "" = every image; else an image reference or repository.
    image: str = Field(default="", max_length=512)
    reason: str = Field(default="", max_length=docker_acceptances.MAX_REASON)
    days: int = Field(
        default=docker_acceptances.DEFAULT_DAYS, ge=1, le=docker_acceptances.MAX_DAYS
    )


@router.post(
    "/vulnerability-acceptances",
    dependencies=[_updates],
    status_code=status.HTTP_201_CREATED,
)
async def accept_api(
    request: Request,
    payload: _AcceptRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Accept (or extend) a critical or high vulnerability for `days` from
    now. The counts, the gate and alerts follow within a minute."""
    await _require_unrestricted(db, user)
    if not docker_acceptances.is_vuln_id_valid(payload.vuln_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid id.")
    row = await docker_acceptances.accept(
        db,
        vuln_id=payload.vuln_id,
        image=payload.image,
        reason=payload.reason,
        days=payload.days,
        actor=user.username,
    )
    await db.commit()
    recompute_vulnerability_acceptances.delay([row.vuln_id])
    await log_event(
        db,
        request=request,
        action="docker.vulnerability.accept",
        summary=f"Accepted {row.vuln_id} for {row.image or 'every image'} until "
        f"{row.expires_at.date().isoformat()} (REST API)",
        target_type="vulnerability",
        target_label=row.vuln_id,
        details={
            "vuln_id": row.vuln_id,
            "image": row.image,
            "reason": row.reason,
            "expires_at": row.expires_at.isoformat(),
        },
    )
    return _acceptance(row)


@router.delete("/vulnerability-acceptances/{acceptance_id}", dependencies=[_updates])
async def revoke_api(
    request: Request,
    acceptance_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    """Revoke an acceptance: the vulnerability counts again."""
    await _require_unrestricted(db, user)
    row = await db.get(DockerVulnerabilityAcceptance, acceptance_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    vuln_id, image = row.vuln_id, row.image
    await db.delete(row)
    await db.commit()
    recompute_vulnerability_acceptances.delay([vuln_id])
    await log_event(
        db,
        request=request,
        action="docker.vulnerability.revoke",
        summary=f"Revoked the acceptance of {vuln_id} for {image or 'every image'} (REST API)",
        target_type="vulnerability",
        target_label=vuln_id,
        details={"vuln_id": vuln_id, "image": image},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
