"""REST API for Docker -> Containers: every container of the visible fleet
(`app.services.docker_fleet`, the same list, filters, sorting and paging
as the web page) and the same actions on several of them at once.

`machine.view` reads (scoped to the machines the token's account can
see); the actions need what the web page's buttons need: `action.power`
for start/stop/restart, `action.updates` for update and scan. Removing
containers stays per machine (`POST /api/v1/machines/{id}/docker/
containers/bulk`), like on the web page.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_fleet
from app.services.access_scope import visible_machines_by_ids
from app.ssh.containers import MAX_BULK_CONTAINERS
from app.ssh.docker_cli import is_container_name_valid
from app.web.routes.machines_docker import bulk_on_machine, bulk_permission

router = APIRouter(prefix="/api/v1/docker", tags=["docker"])
_view = Depends(require_api_permission(Permission.MACHINE_VIEW))


def _row(row: docker_fleet.FleetRow) -> dict[str, Any]:
    c = row.container
    return {
        "key": row.key,
        "machine_id": str(row.machine_id),
        "machine_name": row.machine_name,
        "group": row.group_name,
        "name": row.name,
        "state": c.get("state"),
        "status": c.get("status"),
        "health": c.get("health"),
        "row_state": row.row_state,
        "image": c.get("image"),
        "image_id": row.image_id,
        "image_update": row.image_status,
        "vulnerabilities": row.counts,
        "compose_project": c.get("compose_project"),
        "compose_service": c.get("compose_service"),
        "ports": c.get("ports"),
        "web_links": row.web_links,
        "auto_update": row.auto_update,
        "cpu_percent": c.get("cpu_percent"),
        "mem_bytes": c.get("mem_bytes"),
        "mem_limit_bytes": c.get("mem_limit_bytes"),
    }


@router.get("/containers", dependencies=[_view])
async def docker_fleet_containers_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
    q: str = "",
    state: str = "",
    group: str = "",
    update: bool = False,
    vulns: str = "",
    stack: str = "",
    sort: str = "machine",
    desc: bool = False,
    page: int = 1,
) -> dict[str, Any]:
    """Every container of the visible machines, 100 per page. Filters:
    `q` (machine, name, image, stack, ports, group), `state` (running,
    unhealthy, restarting, paused, exited, created), `group` (id),
    `update` (a newer image exists), `vulns` (critical / high), `stack`
    (Compose project). `sort`: machine, name, image, state, vulns, update."""
    flt = docker_fleet.FleetFilter.parse(
        q=q,
        state=state,
        group=group,
        update="1" if update else "",
        vulns=vulns,
        stack=stack,
        sort=sort,
        desc="1" if desc else "",
        page=page,
    )
    result = await docker_fleet.list_containers(db, user, flt)
    return {
        "containers": [_row(r) for r in result.rows],
        "total": result.total,
        "page": result.page,
        "pages": result.pages,
        "page_size": docker_fleet.PAGE_SIZE,
        "state_counts": result.state_counts,
        "machines": result.machines,
        "with_update": result.with_update,
        "truncated": result.truncated,
    }


class _FleetBulkRequest(BaseModel):
    action: Literal["start", "stop", "restart", "update", "scan"]
    # "<machine id>/<container name>", as `key` in the listing.
    containers: list[str] = Field(default_factory=list, max_length=MAX_BULK_CONTAINERS)


@router.post("/containers/bulk", dependencies=[_view])
async def docker_fleet_containers_bulk_api(
    request: Request,
    body: _FleetBulkRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Start, stop, restart, update or scan containers on several machines
    at once — machine by machine, through the same code as each machine's
    own bulk action, each container audited. Machines the token can't see
    are left out; one without a confirmed host key is reported in
    `errors`."""
    permission = bulk_permission(body.action)
    if permission is None or not user.has_permission(permission):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    selected = {
        machine_id: [n for n in names if is_container_name_valid(n)]
        for machine_id, names in docker_fleet.parse_keys(body.containers).items()
    }
    selected = {m: names for m, names in selected.items() if names}
    if not selected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="No valid containers."
        )
    machines = await visible_machines_by_ids(db, user, list(selected))
    done = 0
    errors: dict[str, str] = {}
    jobs: list[str] = []
    for machine in sorted(machines, key=lambda m: m.name.lower()):
        if not machine.host_key_fingerprint:
            errors[str(machine.id)] = "Confirm the machine's host key fingerprint first."
            continue
        outcome = await bulk_on_machine(
            request, db, machine, user, body.action, selected[machine.id]
        )
        done += outcome.done
        if outcome.scan_job is not None:
            jobs.append(str(outcome.scan_job.id))
        if outcome.error:
            errors[str(machine.id)] = str(outcome.error)
    unknown: list[uuid.UUID] = [m for m in selected if m not in {x.id for x in machines}]
    for machine_id in unknown:
        errors[str(machine_id)] = "Machine not found."
    return {"ok": not errors, "done": done, "errors": errors, "scan_jobs": jobs}
