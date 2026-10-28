"""The Security section (nav: **Security**, `machine.view`): the fleet-wide
view of pending security updates and the fleet-wide installed-package
search — the two pages an operator opens right after a CVE announcement —
the Lynis security audit of every machine (`/security/audit`, see
`app.services.security_audit`), and the critical and high vulnerabilities
in the machines' Docker images, with accepting one until a date
(`/security/containers`, see `app.services.docker_acceptances`).

They used to live under the Machines page's "More actions" menu
(`/machines/security-updates`, `/machines/package-search`); those URLs
redirect here. Both pages are scoped to the machines the account can see
(`app.services.access_scope.machines_visible_to`)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import DockerVulnerabilityAcceptance
from app.db.models.machine import Machine
from app.db.models.machine_package import MachinePackage
from app.db.models.role import Permission
from app.db.models.security_audit import SecurityAudit
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_acceptances, security_audit
from app.services.access_scope import is_restricted, machines_visible_to
from app.services.machine_actions import trigger_security_audits
from app.services.security_updates import load_security_overview_with_gaps
from app.ssh.packages import PackageSource
from app.tasks.docker_jobs import recompute_vulnerability_acceptances
from app.web.templating import t, templates

router = APIRouter(
    prefix="/security", dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))]
)

_PACKAGE_SEARCH_LIMIT = 500


def _tabs(request: Request) -> list[tuple[str, str, str]]:
    return [
        ("updates", t(request, "security.title"), "/security/updates"),
        ("packages", t(request, "machines.actions.package_search"), "/security/packages"),
        ("audit", t(request, "security_audit.tab"), "/security/audit"),
        ("containers", t(request, "security.containers.tab"), "/security/containers"),
    ]


@router.get("")
async def security_index() -> Response:
    return RedirectResponse(url="/security/updates", status_code=303)


@router.get("/updates")
async def security_updates(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Every pending apt security update across the visible fleet, grouped
    by package and version, with the CVEs it fixes and the machines it's
    pending on — see `app.services.security_updates`."""
    rows, undetailed = await load_security_overview_with_gaps(
        db, await machines_visible_to(db, current_user)
    )
    return templates.TemplateResponse(
        request,
        "security/updates.html",
        {"rows": rows, "undetailed": undetailed, "tabs": _tabs(request), "active_tab": "updates"},
    )


@router.get("/packages")
async def package_search(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    pkg_source: str = "",
) -> Response:
    """Fleet-wide "who has package X installed, and what version" — the
    other direction from the per-machine Installed packages panel. Useful
    after a CVE announcement: search the name, see every machine and
    version at once instead of checking machines one by one."""
    results: list[MachinePackage] = []
    truncated = False
    if q.strip():
        # Scoped by joining the machine each row belongs to — a restricted
        # user searching fleet-wide must not learn which packages sit on a
        # machine they can't otherwise see.
        visible_ids = (await machines_visible_to(db, current_user)).with_only_columns(
            Machine.id
        )
        query = (
            select(MachinePackage)
            .options(selectinload(MachinePackage.machine))
            .where(
                MachinePackage.name.ilike(f"%{q.strip()}%"),
                MachinePackage.machine_id.in_(visible_ids),
            )
        )
        if pkg_source in {source.value for source in PackageSource}:
            query = query.where(MachinePackage.source == PackageSource(pkg_source))
        query = query.order_by(MachinePackage.name).limit(_PACKAGE_SEARCH_LIMIT + 1)
        result = await db.execute(query)
        results = list(result.scalars().all())
        truncated = len(results) > _PACKAGE_SEARCH_LIMIT
        results = results[:_PACKAGE_SEARCH_LIMIT]

    return templates.TemplateResponse(
        request,
        "security/packages.html",
        {
            "q": q,
            "pkg_source": pkg_source,
            "results": results,
            "truncated": truncated,
            "tabs": _tabs(request),
            "active_tab": "packages",
        },
    )


@dataclass(frozen=True)
class _AuditRow:
    machine: Machine
    # The newest audit of any outcome, and the newest that succeeded.
    latest: SecurityAudit | None
    audit: SecurityAudit | None
    # The findings that still count (not marked OK on this machine).
    counts: security_audit.Counts | None = None


@router.get("/audit")
async def security_audit_overview(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Every visible machine with its newest security audit: hardening
    index, failed checks, warnings and suggestions (findings marked OK not
    counted), lowest index first, machines never audited last."""
    visible = await machines_visible_to(db, current_user)
    machines = list((await db.execute(visible.order_by(Machine.name))).scalars().all())
    ids = visible.with_only_columns(Machine.id)
    latest = await security_audit.latest_by_machine(db, ids)
    succeeded = await security_audit.latest_by_machine(db, ids, succeeded_only=True)
    suppressed = await security_audit.suppressed_keys_by_machine(db, [m.id for m in machines])
    rows = []
    for m in machines:
        audit = succeeded.get(m.id)
        counts = security_audit.counts(audit, suppressed.get(m.id, set())) if audit else None
        rows.append(_AuditRow(m, latest.get(m.id), audit, counts))
    rows.sort(
        key=lambda r: (
            r.audit is None,
            r.audit is not None and r.audit.hardening_index is None,
            r.audit.hardening_index or 0 if r.audit is not None else 0,
            -(r.counts.failed_checks if r.counts else 0),
            r.machine.name.lower(),
        )
    )
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "security/audit.html",
        {
            "rows": rows,
            "display_status": security_audit.display_status,
            "any_active": any(
                r.latest is not None and security_audit.is_active(r.latest) for r in rows
            ),
            "can_run": current_user.has_permission(Permission.ACTION_UPDATES),
            "csrf_token": csrf_token,
            "started": request.query_params.get("started"),
            "skipped": request.query_params.get("skipped"),
            "tabs": _tabs(request),
            "active_tab": "audit",
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post(
    "/audit/run",
    dependencies=[
        Depends(require_permission(Permission.ACTION_UPDATES)),
        Depends(verify_csrf),
    ],
)
async def run_security_audits(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Start a Lynis audit of every visible machine (those with an audit
    already under way, or no confirmed host key, are skipped)."""
    visible = await machines_visible_to(db, current_user)
    machines = list((await db.execute(visible)).scalars().all())
    audits, skipped = await trigger_security_audits(
        db, machines, started_by=current_user.username
    )
    await log_event(
        db,
        request=request,
        action="machines.bulk.security_audit.run",
        summary=f"Started a security audit (Lynis) of {len(audits)} machines",
        outcome=AuditOutcome.SUCCESS,
        details={
            "started": len(audits),
            "skipped": skipped,
        },
    )
    return RedirectResponse(
        url=f"/security/audit?started={len(audits)}&skipped={skipped}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# --- Container vulnerabilities across the fleet ----------------------------


async def _can_accept(db: AsyncSession, user: User) -> bool:
    """Accepting is fleet-wide (it changes every machine's counts and
    gate), so an account limited to some machine groups can't."""
    return user.has_permission(Permission.ACTION_UPDATES) and not await is_restricted(db, user)


@router.get("/containers")
async def container_vulnerabilities(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
) -> Response:
    """Every critical and high vulnerability in the latest scans of the
    visible machines' Docker images, with how many machines and images
    have it; the accepted ones are marked."""
    visible_ids = (await machines_visible_to(db, current_user)).with_only_columns(Machine.id)
    rows, truncated = await docker_acceptances.fleet_overview(db, visible_ids, query=q)
    can_accept = await _can_accept(db, current_user)
    restricted = await is_restricted(db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "security/containers.html",
        {
            "rows": rows,
            "truncated": truncated,
            "q": q,
            # Who accepted what is fleet-wide: not for a limited account.
            "acceptances": [] if restricted else await docker_acceptances.active(db),
            "can_accept": can_accept,
            "csrf_token": csrf_token,
            "tabs": _tabs(request),
            "active_tab": "containers",
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/containers/{vuln_id}")
async def container_vulnerability(
    request: Request,
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Where one vulnerability is (machine, image, package, fixed version),
    its acceptances, and the form to accept it."""
    if not docker_acceptances.is_vuln_id_valid(vuln_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    visible_ids = (await machines_visible_to(db, current_user)).with_only_columns(Machine.id)
    found = await docker_acceptances.occurrences(db, vuln_id, visible_ids)
    restricted = await is_restricted(db, current_user)
    acceptances = [a for a in await docker_acceptances.active(db) if a.vuln_id == vuln_id]
    if restricted and not found:
        acceptances = []
    repositories = sorted({docker_acceptances.repository_key(o.image_ref) for o in found})
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "security/container_vulnerability.html",
        {
            "vuln_id": vuln_id,
            "occurrences": found,
            "acceptances": acceptances,
            "repositories": repositories,
            "can_accept": await _can_accept(db, current_user),
            "default_days": docker_acceptances.DEFAULT_DAYS,
            "max_days": docker_acceptances.MAX_DAYS,
            "csrf_token": csrf_token,
            "notice": request.query_params.get("saved"),
            "tabs": _tabs(request),
            "active_tab": "containers",
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post(
    "/containers/{vuln_id}/accept",
    dependencies=[
        Depends(require_permission(Permission.ACTION_UPDATES)),
        Depends(verify_csrf),
    ],
)
async def accept_container_vulnerability(
    request: Request,
    vuln_id: str,
    image: str = Form(""),
    reason: str = Form(""),
    days: int = Form(docker_acceptances.DEFAULT_DAYS),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Accept a vulnerability for every image or one image repository
    until `days` from now; the counts follow in the background."""
    if not await _can_accept(db, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    if not docker_acceptances.is_vuln_id_valid(vuln_id) or not 1 <= days <= (
        docker_acceptances.MAX_DAYS
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")
    row = await docker_acceptances.accept(
        db, vuln_id=vuln_id, image=image, reason=reason, days=days, actor=current_user.username
    )
    await db.commit()
    recompute_vulnerability_acceptances.delay([vuln_id])
    await log_event(
        db,
        request=request,
        action="docker.vulnerability.accept",
        summary=f"Accepted {vuln_id} for {row.image or 'every image'} until "
        f"{row.expires_at.date().isoformat()}",
        outcome=AuditOutcome.SUCCESS,
        target_type="vulnerability",
        target_label=vuln_id,
        details={
            "vuln_id": vuln_id,
            "image": row.image,
            "reason": row.reason,
            "expires_at": row.expires_at.isoformat(),
        },
    )
    return RedirectResponse(
        url=f"/security/containers/{quote(vuln_id, safe='')}?saved=accepted",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/containers/acceptances/{acceptance_id}/revoke",
    dependencies=[
        Depends(require_permission(Permission.ACTION_UPDATES)),
        Depends(verify_csrf),
    ],
)
async def revoke_container_vulnerability(
    request: Request,
    acceptance_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not await _can_accept(db, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
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
        summary=f"Revoked the acceptance of {vuln_id} for {image or 'every image'}",
        outcome=AuditOutcome.SUCCESS,
        target_type="vulnerability",
        target_label=vuln_id,
        details={"vuln_id": vuln_id, "image": image},
    )
    return RedirectResponse(
        url=f"/security/containers/{quote(vuln_id, safe='')}?saved=revoked",
        status_code=status.HTTP_303_SEE_OTHER,
    )
