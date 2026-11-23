"""REST API for the Map pages, a machine's network picture and one Proxmox
VE guest — the same reads and the same write as the web UI, under the same
permissions, scoped to the machines the token's account can see.

- `GET /api/v1/map/where?q=` — what runs where: Proxmox VE hosts with
  their guests on that node (each linked to the managed machine it is),
  and every machine's Docker stacks with their containers and web links.
- `GET /api/v1/map/networks` — the machines by IPv4 network, with each
  network's gateway, and the machines whose address isn't known yet.
- `GET /api/v1/proxmox/capacity?cores=&memory_gb=&disk_gb=` — every Proxmox
  VE node: cores and vCPUs given to guests, memory and memory given to
  running guests (`overcommitted`), guest storages and their free space;
  with any of the three parameters, `fits` lists every node with whether a
  guest of that size fits and, if not, why (`offline`, `cores`, `memory`,
  `storage`), the best first.
- `GET /api/v1/machines/{id}/network/topology` — the machine's network as
  nodes (cards, bonds, bridges, VLANs, guests, Docker) and lines with the
  traffic over each in bytes per second; `null` without a bridge or bond.
- `GET /api/v1/machines/{id}/proxmox/guests/{vmid}` — one guest: its row
  of `GET .../proxmox` → `guests` (with I/O rates) and its configuration
  and IP addresses (`details`, null before a facts refresh by 0.145.0).
- `PUT /api/v1/machines/{id}/proxmox/guests/{vmid}/notes` — `{"notes":
  "..."}` writes the guest's notes (its Proxmox `description`; empty
  deletes them). `machine.manage`, audited as `machine.guest.notes`.

All `machine.view` but the last. The guest's console has no API, like the
terminal it is (see `api_v1.py`)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import fleet_map, live_overview, network_topology, proxmox_capacity
from app.ssh import proxmox
from app.web.routes.api_v1 import _get_machine_or_404
from app.web.routes.fleet_map import fit_request, visible_machines
from app.web.routes.machines_proxmox import guest_details, set_notes

router = APIRouter(prefix="/api/v1")

_view = Depends(require_api_permission(Permission.MACHINE_VIEW))
_manage = Depends(require_api_permission(Permission.MACHINE_MANAGE))


@router.get("/map/where", dependencies=[_view])
async def map_where_api(
    q: str = Query("", max_length=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    return fleet_map.where_dict(fleet_map.where(await visible_machines(db, user), q))


@router.get("/map/networks", dependencies=[_view])
async def map_networks_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    return fleet_map.networks_dict(*fleet_map.networks(await visible_machines(db, user)))


@router.get("/proxmox/capacity", dependencies=[_view])
async def proxmox_capacity_api(
    cores: str = Query("", max_length=16),
    memory_gb: str = Query("", max_length=16),
    disk_gb: str = Query("", max_length=16),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    nodes = proxmox_capacity.fleet_nodes(await visible_machines(db, user))
    wanted = fit_request(cores, memory_gb, disk_gb)
    result: dict[str, Any] = {"nodes": [n.as_dict() for n in nodes]}
    if wanted:
        result["fits"] = [
            {
                "cluster": f.node.cluster,
                "node": f.node.node,
                "fits": f.fits,
                "reasons": list(f.reasons),
                "memory_left_bytes": f.mem_left_bytes,
            }
            for f in proxmox_capacity.fits(nodes, *wanted)
        ]
    return result


@router.get("/machines/{machine_id}/network/topology", dependencies=[_view])
async def machine_topology_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any] | None:
    machine = await _get_machine_or_404(machine_id, db, user)
    samples = await live_overview.load_recent(db, machine.id)
    topology = network_topology.of_machine(
        machine,
        samples[0] if samples else None,
        samples[1] if len(samples) > 1 else None,
        with_links=False,
    )
    return topology.as_dict() if topology else None


def _guest_or_404(guests: list[dict[str, Any]] | None, vmid: int) -> dict[str, Any]:
    guest = proxmox.find_guest(guests, vmid)
    if guest is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such guest.")
    return guest


@router.get("/machines/{machine_id}/proxmox/guests/{vmid}", dependencies=[_view])
async def proxmox_guest_api(
    machine_id: uuid.UUID,
    vmid: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    guest = _guest_or_404(machine.pve_guests, vmid)
    return {"guest": guest, "details": guest_details(machine, vmid)}


class GuestNotes(BaseModel):
    notes: str = Field("", max_length=16384)


@router.put("/machines/{machine_id}/proxmox/guests/{vmid}/notes", dependencies=[_manage])
async def proxmox_guest_notes_api(
    request: Request,
    machine_id: uuid.UUID,
    vmid: int,
    body: GuestNotes,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    guest = _guest_or_404(machine.pve_guests, vmid)
    error = await set_notes(request, db, machine, guest, body.notes)
    if error:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"notes": proxmox.clean_notes(body.notes)}
