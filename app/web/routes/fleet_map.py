"""Map (nav: **Map**, `machine.view`), three tabs over the machines the
account can see:

- `/map` — what runs where: Proxmox VE hosts → VMs and containers →
  Docker stacks → containers and their web links (`?q=` filters by any
  name, image or address on the way). `app.services.fleet_map.where`.
- `/map/networks` — the machines by IPv4 network, with each network's
  gateway. `app.services.fleet_map.networks`.
- `/map/capacity` — every Proxmox VE node: CPU, memory and guest storage,
  what is given to guests (over-commit), and where a new guest of a given
  size fits (`?cores=&memory_gb=&disk_gb=`).
  `app.services.proxmox_capacity`.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, require_permission
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import fleet_map, proxmox_capacity
from app.services.access_scope import machines_visible_to
from app.web.templating import t, templates

router = APIRouter(dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))])

GIB = 1024**3
MAX_CORES = 1024
MAX_MEMORY_GB = 65536
MAX_DISK_GB = 1048576


async def visible_machines(db: AsyncSession, user: User) -> list[Machine]:
    query = await machines_visible_to(db, user)
    result = await db.execute(query.where(Machine.is_active.is_(True)))
    return list(result.scalars().all())


def _tabs(request: Request) -> list[tuple[str, str, str]]:
    return [
        ("where", t(request, "map.tab.where"), "/map"),
        ("networks", t(request, "map.tab.networks"), "/map/networks"),
        ("capacity", t(request, "map.tab.capacity"), "/map/capacity"),
    ]


@router.get("/map")
async def map_where(
    request: Request,
    q: str = Query("", max_length=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    entries = fleet_map.where(await visible_machines(db, current_user), q)
    return templates.TemplateResponse(
        request,
        "map/where.html",
        {"entries": entries, "q": q, "tabs": _tabs(request), "active_tab": "where"},
    )


@router.get("/map/networks")
async def map_networks(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    networks, unknown = fleet_map.networks(await visible_machines(db, current_user))
    return templates.TemplateResponse(
        request,
        "map/networks.html",
        {
            "networks": networks,
            "unknown": unknown,
            "tabs": _tabs(request),
            "active_tab": "networks",
        },
    )


def fit_request(cores: str, memory_gb: str, disk_gb: str) -> tuple[int, int, int] | None:
    """(cores, memory bytes, disk bytes) from the form, None when nothing
    was asked. Out-of-range or unreadable numbers count as 0."""

    def number(text: str, limit: int) -> float:
        try:
            value = float(text.replace(",", "."))
        except ValueError:
            return 0
        return value if 0 < value <= limit else 0

    wanted = (
        int(number(cores, MAX_CORES)),
        int(number(memory_gb, MAX_MEMORY_GB) * GIB),
        int(number(disk_gb, MAX_DISK_GB) * GIB),
    )
    return wanted if any(wanted) else None


@router.get("/map/capacity")
async def map_capacity(
    request: Request,
    cores: str = Query("", max_length=16),
    memory_gb: str = Query("", max_length=16),
    disk_gb: str = Query("", max_length=16),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    nodes = proxmox_capacity.fleet_nodes(await visible_machines(db, current_user))
    wanted = fit_request(cores, memory_gb, disk_gb)
    fits = proxmox_capacity.fits(nodes, *wanted) if wanted else None
    return templates.TemplateResponse(
        request,
        "map/capacity.html",
        {
            "nodes": nodes,
            "fits": fits,
            "best": next((f for f in fits or [] if f.fits), None),
            "fit_of": {f"{f.node.cluster or ''}/{f.node.node}": f for f in fits or []},
            "form": {"cores": cores, "memory_gb": memory_gb, "disk_gb": disk_gb},
            "tabs": _tabs(request),
            "active_tab": "capacity",
        },
    )
