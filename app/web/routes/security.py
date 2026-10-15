"""The Security section (nav: **Security**, `machine.view`): the fleet-wide
view of pending security updates and the fleet-wide installed-package
search — the two pages an operator opens right after a CVE announcement —
and the Lynis security audit of every machine (`/security/audit`, see
`app.services.security_audit`).

They used to live under the Machines page's "More actions" menu
(`/machines/security-updates`, `/machines/package-search`); those URLs
redirect here. Both pages are scoped to the machines the account can see
(`app.services.access_scope.machines_visible_to`)."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import Machine
from app.db.models.machine_package import MachinePackage
from app.db.models.role import Permission
from app.db.models.security_audit import SecurityAudit
from app.db.models.user import User
from app.db.session import get_db
from app.services import security_audit
from app.services.access_scope import machines_visible_to
from app.services.machine_actions import trigger_security_audits
from app.services.security_updates import load_security_overview_with_gaps
from app.ssh.packages import PackageSource
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


@router.get("/audit")
async def security_audit_overview(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Every visible machine with its newest Lynis audit: hardening index,
    warnings and suggestions, lowest index first, machines never audited
    last."""
    visible = await machines_visible_to(db, current_user)
    machines = list((await db.execute(visible.order_by(Machine.name))).scalars().all())
    ids = visible.with_only_columns(Machine.id)
    latest = await security_audit.latest_by_machine(db, ids)
    succeeded = await security_audit.latest_by_machine(db, ids, succeeded_only=True)
    rows = [_AuditRow(m, latest.get(m.id), succeeded.get(m.id)) for m in machines]
    rows.sort(
        key=lambda r: (
            r.audit is None,
            r.audit.hardening_index or 0 if r.audit is not None else 0,
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
        set_csrf_cookie(response, csrf_token)
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
    install: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Start a Lynis audit of every visible machine (those with an audit
    already under way, or no confirmed host key, are skipped)."""
    visible = await machines_visible_to(db, current_user)
    machines = list((await db.execute(visible)).scalars().all())
    install_if_missing = install == "on"
    audits, skipped = await trigger_security_audits(
        db, machines, install_if_missing=install_if_missing, started_by=current_user.username
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
            "install_if_missing": install_if_missing,
        },
    )
    return RedirectResponse(
        url=f"/security/audit?started={len(audits)}&skipped={skipped}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
