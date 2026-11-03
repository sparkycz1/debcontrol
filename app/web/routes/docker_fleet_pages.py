"""Docker across the fleet, besides containers (`docker_fleet`): stacks,
images, volumes, networks, backups, hosts and jobs of every visible
machine — the same tabs as a machine's own Docker tab, each a table with
the same actions, run machine by machine through the same code
(`docker_fleet_actions` → `docker_ops`).

The lists read what is stored (`app.services.docker_fleet_lists`); the
*Refresh* button reads every machine's images, volumes, networks and
projects again in the background (one Celery task per machine) and the
page reloads by itself when they arrive (`live-fleet.js`).
"""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_fleet_lists as lists
from app.services.access_scope import groups_visible_to
from app.ssh.docker_prune import PruneOptions
from app.web.messages import LocalizedText
from app.web.routes import docker_fleet_actions as fleet_actions
from app.web.routes import docker_ops
from app.web.routes.docker_fleet import tabs
from app.web.routes.machines_docker_common import redirect
from app.web.templating import templates

router = APIRouter(
    prefix="/docker", dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))]
)

PAGES = ("stacks", "images", "volumes", "networks", "backups", "hosts", "jobs")
# Lists that read the stored inventory (and so offer *Refresh*).
INVENTORY_PAGES = ("stacks", "images", "volumes", "networks")


def _back(kind: str, value: str) -> str:
    return value if value.startswith(f"/docker/{kind}") else f"/docker/{kind}"


async def _page(
    request: Request, db: AsyncSession, user: User, kind: str, q: str, group: str, show: str,
    page: int,
) -> Response:
    flt = lists.FleetListFilter.parse(kind, q=q, group=group, show=show, page=page)
    settings = await get_or_create_app_settings(db) if kind == "hosts" else None
    result = await lists.list_items(db, user, kind, flt, settings=settings)
    groups = (await db.execute(await groups_visible_to(db, user))).scalars().all()
    query = {
        key: value
        for key, value in (
            ("q", flt.q),
            ("group", str(flt.group_id) if flt.group_id else ""),
            ("show", flt.show),
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
        return f"/docker/{kind}" + (f"?{encoded}" if encoded else "")

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        f"docker/fleet/{kind}.html",
        {
            "kind": kind,
            "result": result,
            "flt": flt,
            "shows": lists.SHOW.get(kind, ()),
            "groups": sorted(groups, key=lambda g: g.name.lower()),
            "url_with": url_with,
            "back": url_with(page=flt.page if flt.page > 1 else None),
            "csrf_token": csrf_token,
            "tabs": tabs(request, user),
            "active_tab": kind,
            "inventory_page": kind in INVENTORY_PAGES,
            "actions": {
                action: bool(fleet_actions.allowed(user, kind, action))
                for action in fleet_actions.ACTIONS.get(kind, {})
            },
            "can_prune": user.has_permission(Permission.ACTION_UPDATES),
            "can_power": user.has_permission(Permission.ACTION_POWER),
            "can_updates": user.has_permission(Permission.ACTION_UPDATES),
            "can_terminal": user.has_permission(Permission.ACTION_TERMINAL),
            "can_settings": user.has_permission(Permission.SETTINGS_MANAGE),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


def _list_route(kind: str) -> None:
    async def page_view(
        request: Request,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user),
        q: str = "",
        group: str = "",
        show: str = "",
        page: int = 1,
    ) -> Response:
        return await _page(request, db, current_user, kind, q, group, show, page)

    page_view.__name__ = f"fleet_docker_{kind}"
    page_view.__doc__ = f"Docker → {kind.capitalize()} of every visible machine."
    router.add_api_route(f"/{kind}", page_view, methods=["GET"], name=f"fleet_docker_{kind}")


for _kind in PAGES:
    _list_route(_kind)


@router.post("/{kind}/bulk", dependencies=[Depends(verify_csrf)])
async def fleet_docker_bulk(
    request: Request,
    kind: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """A row's menu or the buttons under a list: the action runs on each
    machine with selected rows, one machine after another."""
    if kind not in fleet_actions.ACTIONS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    form = await request.form()
    action = str(form.get("action") or "")
    back = _back(kind, str(form.get("back") or ""))
    permitted = fleet_actions.allowed(current_user, kind, action)
    if permitted is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")
    if not permitted:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    selected = fleet_actions.parse_keys([str(v) for v in form.getlist("item")])
    if not selected:
        return redirect(back, error=LocalizedText(request, "docker.bulk.none_selected"))
    outcome = await fleet_actions.run(request, db, current_user, kind, action, selected)
    if len(outcome.jobs) == 1 and outcome.done == 1 and not outcome.errors:
        job = outcome.jobs[0]
        return redirect(f"/machines/{job.machine_id}/docker/jobs/{job.id}")
    notice = (
        LocalizedText(request, f"docker_fleet.done.{kind}", count=outcome.done)
        if outcome.done
        else None
    )
    error = "; ".join(outcome.errors[:20]) or None
    if not notice and not error:
        error = LocalizedText(request, "docker.bulk.none_selected")
    return redirect(back, notice=notice, error=error)


@router.post(
    "/prune",
    dependencies=[Depends(require_permission(Permission.ACTION_UPDATES)), Depends(verify_csrf)],
)
async def fleet_docker_prune(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The clean-up on every visible machine with readable Docker (or one
    group's): one job each. Every unused named volume is never removed
    across machines (that needs each machine's name typed)."""
    form = await request.form()
    back_kind = str(form.get("from") or "images")
    back = f"/docker/{back_kind if back_kind in PAGES else 'images'}"
    options = PruneOptions(
        containers=form.get("containers") == "1",
        images=form.get("images") == "1",
        all_images=form.get("all_images") == "1",
        networks=form.get("networks") == "1",
        volumes=form.get("volumes") == "1",
        all_volumes=form.get("all_volumes") == "1",
        build_cache=form.get("build_cache") == "1",
    )
    if not options.anything:
        return redirect(back, error=LocalizedText(request, "docker.prune.nothing"))
    flt = lists.FleetListFilter.parse("images", group=str(form.get("group") or ""))
    machines = await lists.docker_machines(db, current_user, flt.group_id)
    outcome = await fleet_actions.prune(request, db, current_user, machines, options)
    notice = (
        LocalizedText(request, "docker_fleet.done.prune", count=outcome.done)
        if outcome.done
        else None
    )
    return redirect(back, notice=notice, error="; ".join(outcome.errors[:20]) or None)


@router.post("/refresh", dependencies=[Depends(verify_csrf)])
async def fleet_docker_refresh(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Read every visible machine's images, volumes, networks and projects
    again, in the background (read-only, like opening each machine's
    pages). A machine read in the last minute is skipped."""
    form = await request.form()
    back_kind = str(form.get("from") or "images")
    back = f"/docker/{back_kind if back_kind in PAGES else 'images'}"
    flt = lists.FleetListFilter.parse("images", group=str(form.get("group") or ""))
    machines = await lists.docker_machines(db, current_user, flt.group_id)
    queued = docker_ops.refresh_fleet(machines)
    notice = LocalizedText(request, "docker_fleet.refresh_queued", count=queued)
    return redirect(back, notice=notice)
