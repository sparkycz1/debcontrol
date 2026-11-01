"""Docker across the fleet (`/docker`): every container of every visible
machine in one table (`app.services.docker_fleet`), with the same
start/stop/restart, update and scan actions as a machine's own
containers table — run machine by machine through the same code
(`machines_docker.bulk_on_machine`), with the same permissions.

Container vulnerabilities across the fleet stay under Security →
Containers; the tab here links there.
"""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_fleet, docker_overview
from app.services.access_scope import groups_visible_to, visible_machines_by_ids
from app.ssh.containers import MAX_BULK_CONTAINERS
from app.ssh.docker_cli import is_container_name_valid
from app.web.messages import LocalizedText
from app.web.routes.machines_docker import bulk_on_machine, bulk_permission
from app.web.routes.machines_docker_common import redirect
from app.web.templating import t, templates

router = APIRouter(
    prefix="/docker", dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))]
)


def tabs(request: Request, user: User) -> list[tuple[str, str, str]]:
    """Docker's own tabs; registries and shared variables (their logins
    and secrets reach the machines' Docker) only with `action.terminal`."""
    items = [("containers", t(request, "docker_fleet.tab.containers"), "/docker/containers")]
    if user.has_permission(Permission.ACTION_TERMINAL):
        items += [
            ("registries", t(request, "docker_fleet.tab.registries"), "/docker/registries"),
            ("variables", t(request, "docker_fleet.tab.variables"), "/docker/variables"),
        ]
    items.append(
        ("vulnerabilities", t(request, "security.containers.tab"), "/security/containers")
    )
    return items


@router.get("")
async def docker_index() -> Response:
    return RedirectResponse(url="/docker/containers", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/containers")
async def fleet_containers(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    state: str = "",
    group: str = "",
    update: str = "",
    vulns: str = "",
    stack: str = "",
    sort: str = "",
    desc: str = "",
    page: int = 1,
) -> Response:
    """Every container of the visible fleet, filtered and paged."""
    flt = docker_fleet.FleetFilter.parse(
        q=q, state=state, group=group, update=update, vulns=vulns, stack=stack,
        sort=sort, desc=desc, page=page,
    )
    result = await docker_fleet.list_containers(db, current_user, flt)
    groups = (await db.execute(await groups_visible_to(db, current_user))).scalars().all()
    query: dict[str, str] = {
        key: value
        for key, value in (
            ("q", flt.q),
            ("state", flt.state),
            ("group", str(flt.group_id) if flt.group_id else ""),
            ("update", "1" if flt.update else ""),
            ("vulns", flt.vulns),
            ("stack", flt.stack),
            ("sort", flt.sort if flt.sort != "machine" else ""),
            ("desc", "1" if flt.desc else ""),
        )
        if value
    }

    def url_with(**changes: str | int | None) -> str:
        merged: dict[str, str] = dict(query)
        for key, value in changes.items():
            if value in (None, ""):
                merged.pop(key, None)
            else:
                merged[key] = str(value)
        encoded = urlencode(merged)
        return "/docker/containers" + (f"?{encoded}" if encoded else "")

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "docker/containers.html",
        {
            "page": result,
            "flt": flt,
            "groups": sorted(groups, key=lambda g: g.name.lower()),
            "state_groups": docker_overview.STATE_GROUPS,
            "url_with": url_with,
            "csrf_token": csrf_token,
            "tabs": tabs(request, current_user),
            "active_tab": "containers",
            "can_power": current_user.has_permission(Permission.ACTION_POWER),
            "can_updates": current_user.has_permission(Permission.ACTION_UPDATES),
            "back": url_with(),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/containers/bulk", dependencies=[Depends(verify_csrf)])
async def fleet_containers_bulk(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The buttons under the fleet table: the action runs on each machine
    with selected containers, one machine after another."""
    form = await request.form()
    action = str(form.get("action") or "")
    back = str(form.get("back") or "/docker/containers")
    if not back.startswith("/docker/containers"):
        back = "/docker/containers"
    permission = bulk_permission(action)
    if permission is None or action == "remove":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")
    if not current_user.has_permission(permission):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    selected = docker_fleet.parse_keys([str(v) for v in form.getlist("container")])
    total = 0
    for machine_id in list(selected):
        names = [n for n in selected[machine_id] if is_container_name_valid(n)]
        names = names[: max(0, MAX_BULK_CONTAINERS - total)]
        total += len(names)
        selected[machine_id] = names
    selected = {m: names for m, names in selected.items() if names}
    if not selected:
        return redirect(back, error=LocalizedText(request, "docker.bulk.none_selected"))
    machines = await visible_machines_by_ids(db, current_user, list(selected))
    done = 0
    errors: list[str] = []
    for machine in sorted(machines, key=lambda m: m.name.lower()):
        if not machine.host_key_fingerprint:
            errors.append(f"{machine.name}: {t(request, 'docker_fleet.no_host_key')}")
            continue
        outcome = await bulk_on_machine(
            request, db, machine, current_user, action, selected[machine.id]
        )
        done += outcome.done
        if outcome.error:
            errors.append(f"{machine.name}: {getattr(outcome.error, 'localized', outcome.error)}")
    notice_key = {
        "update": "docker.update.queued",
        "scan": "docker_fleet.scans_queued",
    }.get(action, f"docker.bulk.done_{action}")
    notice = LocalizedText(request, notice_key, count=done) if done else None
    return redirect(back, notice=notice, error="; ".join(errors) or None)
