"""The Security section (nav: **Security**, `machine.view`): the fleet-wide
view of pending security updates and the fleet-wide installed-package
search — the two pages an operator opens right after a CVE announcement.

They used to live under the Machines page's "More actions" menu
(`/machines/security-updates`, `/machines/package-search`); those URLs
redirect here. Both pages are scoped to the machines the account can see
(`app.services.access_scope.machines_visible_to`)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.dependencies import get_current_user, require_permission
from app.db.models.machine import Machine
from app.db.models.machine_package import MachinePackage
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services.access_scope import machines_visible_to
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
