"""REST API for the fleet-wide Docker tabs besides containers: stacks,
images, volumes, networks, backups, hosts and jobs of every visible
machine (`app.services.docker_fleet_lists`, the same lists, filters and
paging as the web pages) and the same actions on several rows at once
(`app.web.routes.docker_fleet_actions`, which runs each machine's own
code with its permission and audit entries).

`machine.view` reads; each action needs exactly what the web page's
button needs (see `docker_fleet_actions.ACTIONS`): `action.power` for
start/stop/restart/down of stacks and restarting Docker, `action.updates`
for up/update of stacks, image pull/scan/remove, backups and the
clean-up, `machine.manage` for *Check now*, `settings.manage` +
`action.terminal` for writing daemon.json.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user, require_api_permission
from app.core.app_settings import get_or_create_app_settings
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_fleet_lists as lists
from app.ssh.docker_prune import PruneOptions
from app.web.routes import docker_fleet_actions as fleet_actions
from app.web.routes import docker_ops
from app.web.routes.api_v1_docker import _job

router = APIRouter(prefix="/api/v1/docker", tags=["docker"])
_view = Depends(require_api_permission(Permission.MACHINE_VIEW))
_updates = Depends(require_api_permission(Permission.ACTION_UPDATES))


def _row(row: lists.FleetItem) -> dict[str, Any]:
    item = row.item
    if "job" in item:
        item = _job(item["job"])
    return {
        **item,
        "key": row.key,
        "machine_id": str(row.machine_id),
        "machine_name": row.machine_name,
        "group": row.group_name,
        # What `key` names on the machine: a project, image reference (or
        # id), volume, network, backup id, the machine itself, a job id.
        "item_id": row.ident,
        "own": row.is_own,
    }


def _list_route(kind: str) -> None:
    async def list_view(
        db: AsyncSession = Depends(get_db),
        user: User = Depends(get_api_token_user),
        q: str = "",
        group: str = "",
        show: str = "",
        page: int = 1,
    ) -> dict[str, Any]:
        flt = lists.FleetListFilter.parse(kind, q=q, group=group, show=show, page=page)
        settings = await get_or_create_app_settings(db) if kind == "hosts" else None
        result = await lists.list_items(db, user, kind, flt, settings=settings)
        return {
            kind: [_row(r) for r in result.rows],
            "total": result.total,
            "page": result.page,
            "pages": result.pages,
            "page_size": lists.PAGE_SIZE,
            "machines": result.machines,
            "truncated": result.truncated,
            "oldest_read": result.oldest_read,
            "never_read": result.never_read,
        }

    shows = ", ".join(lists.SHOW.get(kind, ())) or "none"
    list_view.__name__ = f"docker_fleet_{kind}_api"
    list_view.__doc__ = (
        f"Docker {kind} of every visible machine, {lists.PAGE_SIZE} per page "
        f"(jobs: the newest {lists.JOBS_LIMIT}). Filters: `q` (text), `group` "
        f"(id), `show` ({shows}). Each row's `key` (`<machine id>/<id>`) is "
        "what the bulk action takes."
    )
    router.add_api_route(
        f"/{kind}", list_view, methods=["GET"], dependencies=[_view], name=list_view.__name__
    )


for _kind in lists.KINDS:
    _list_route(_kind)


class _BulkRequest(BaseModel):
    action: str = Field(max_length=32)
    # "<machine id>/<id>", as `key` in the listing.
    items: list[str] = Field(default_factory=list, max_length=fleet_actions.MAX_ITEMS)


@router.post("/{kind}/bulk", dependencies=[_view])
async def docker_fleet_bulk_api(
    request: Request,
    kind: Literal["stacks", "images", "backups", "hosts"],
    body: _BulkRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Run one action on the given rows, machine by machine, through the
    same code as each machine's own page. Actions: stacks start, stop,
    restart, down, up, update; images pull, scan, remove; backups run,
    check, forget, verify; hosts check, apply (write daemon.json),
    restart (Docker; never on the machine running debcontrol). Rows of
    machines the token can't see, and invalid ones, count in `skipped`."""
    permitted = fleet_actions.allowed(user, kind, body.action)
    if permitted is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown action.")
    if not permitted:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    selected = fleet_actions.parse_keys(body.items)
    if not selected:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid items.")
    outcome = await fleet_actions.run(request, db, user, kind, body.action, selected)
    return {
        "ok": not outcome.errors,
        "done": outcome.done,
        "skipped": outcome.skipped,
        "errors": outcome.errors,
        "jobs": [str(j.id) for j in outcome.jobs],
    }


class _PruneRequest(BaseModel):
    containers: bool = False
    images: bool = False
    all_images: bool = False
    networks: bool = False
    volumes: bool = False
    build_cache: bool = False
    group: str = ""


@router.post("/prune", dependencies=[_updates])
async def docker_fleet_prune_api(
    request: Request,
    body: _PruneRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """The clean-up on every visible machine with readable Docker (or one
    `group`'s), one job each. Unused named volumes are never removed
    across machines: use `POST /api/v1/machines/{id}/docker/prune` with
    the machine's name for that."""
    options = PruneOptions(
        containers=body.containers,
        images=body.images,
        all_images=body.all_images,
        networks=body.networks,
        volumes=body.volumes,
        build_cache=body.build_cache,
    )
    if not options.anything:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nothing selected.")
    flt = lists.FleetListFilter.parse("images", group=body.group)
    machines = await lists.docker_machines(db, user, flt.group_id)
    outcome = await fleet_actions.prune(request, db, user, machines, options)
    return {
        "ok": not outcome.errors,
        "done": outcome.done,
        "errors": outcome.errors,
        "jobs": [str(j.id) for j in outcome.jobs],
    }


class _RefreshRequest(BaseModel):
    group: str = ""


@router.post("/refresh", dependencies=[_view])
async def docker_fleet_refresh_api(
    body: _RefreshRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Read images, volumes, networks and Compose projects again on every
    visible machine (or one `group`'s), in the background — read-only.
    A machine read in the last minute is skipped; `queued` counts the
    rest."""
    flt = lists.FleetListFilter.parse("images", group=body.group)
    machines = await lists.docker_machines(db, user, flt.group_id)
    queued = docker_ops.refresh_fleet(machines)
    return {"queued": queued, "machines": len(machines)}
