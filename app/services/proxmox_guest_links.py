"""Which managed machine is which Proxmox guest.

A Proxmox VE host reports its VMs and containers (`Machine.pve_guests`);
some of those guests are machines debcontrol manages too. This pairs them
up, so a guest row can link to its machine and a machine can say "runs on
pve1 as VM 111".

The pairing is by name: a guest's name equals the machine's name, its
discovered hostname, or the first label of either (`web1` for
`web1.example.com`), ignoring case. A guest whose name pairs nothing is
then paired by address: one of the IP addresses the host read for it
(`Machine.pve_guest_details`, the QEMU guest agent or `lxc-info`) is the
address debcontrol connects to. A pairing is only made when it is
unambiguous — one machine for the guest, one guest for the machine.
Every node of a cluster reports the same guests; then the node the guest
runs on is the one named.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.user import User
from app.services.access_scope import machines_visible_to


class _Named(Protocol):
    """What pairing needs of a machine: a full `Machine` or a light row."""

    @property
    def id(self) -> uuid.UUID:
        """The machine's id."""

    @property
    def name(self) -> str:
        """The name it is managed under."""

    @property
    def discovered_hostname(self) -> str | None:
        """The hostname it reported, if any."""


@dataclass(frozen=True)
class GuestHost:
    """The Proxmox host a machine runs on, and as which guest."""

    machine_id: uuid.UUID
    machine_name: str
    vmid: int
    type: str
    status: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "machine_id": str(self.machine_id),
            "machine_name": self.machine_name,
            "vmid": self.vmid,
            "type": self.type,
            "status": self.status,
        }


def names_of(machine: _Named) -> frozenset[str]:
    """Every name a guest may carry to be this machine, lowercased."""
    names: set[str] = set()
    for value in (machine.name, machine.discovered_hostname):
        cleaned = (value or "").strip().lower()
        if cleaned:
            names.add(cleaned)
            names.add(cleaned.split(".", 1)[0])
    names.discard("")
    return frozenset(names)


def _guest_name(guest: dict[str, Any]) -> str:
    return str(guest.get("name") or "").strip().lower()


def find_host(
    machine: _Named, hypervisors: Iterable[tuple[_Named, list[dict[str, Any]] | None]]
) -> GuestHost | None:
    """The hypervisor `machine` runs on, among `(host, its guests)` pairs —
    None when no guest carries its name, or when guests with different ids
    do (two different guests with one name: not ours to guess)."""
    wanted = names_of(machine)
    hypervisors = list(hypervisors)
    found: list[tuple[_Named, dict[str, Any]]] = []
    for host, guests in hypervisors:
        if host.id == machine.id:
            continue
        found.extend(
            (host, guest)
            for guest in guests or []
            if not guest.get("template") and _guest_name(guest) in wanted
        )
    if not found:
        found = _by_address(machine, hypervisors)
    if not found:
        return None
    if len({(guest.get("vmid"), guest.get("type")) for _host, guest in found}) != 1:
        return None
    # One guest, reported by every node of its cluster: name the node it is on.
    node = str(found[0][1].get("node") or "").lower()
    found.sort(key=lambda pair: (node not in names_of(pair[0]), pair[0].name.lower()))
    host, guest = found[0]
    vmid = guest.get("vmid")
    if not isinstance(vmid, int):
        return None
    return GuestHost(
        machine_id=host.id,
        machine_name=host.name,
        vmid=vmid,
        type=str(guest.get("type") or ""),
        status=str(guest.get("status") or ""),
    )


def _by_address(
    machine: _Named, hypervisors: list[tuple[_Named, list[dict[str, Any]] | None]]
) -> list[tuple[_Named, dict[str, Any]]]:
    """The guests whose addresses (as their host read them) include the
    address debcontrol reaches `machine` at."""
    address = str(getattr(machine, "ip_address", "") or "").strip().lower()
    if not address:
        return []
    found: list[tuple[_Named, dict[str, Any]]] = []
    for host, guests in hypervisors:
        details = getattr(host, "pve_guest_details", None) or {}
        if host.id == machine.id or not isinstance(details, dict):
            continue
        for guest in guests or []:
            ips = (details.get(str(guest.get("vmid"))) or {}).get("ips") or []
            if not guest.get("template") and address in [str(ip).lower() for ip in ips]:
                found.append((host, guest))
    return found


def pair_guests[M: _Named](
    host_id: uuid.UUID,
    guests: list[dict[str, Any]] | None,
    machines: Iterable[M],
    details: dict[str, Any] | None = None,
) -> dict[int, M]:
    """`{vmid: machine}` for the guests of one host that are managed
    machines. A name shared by two guests, or by two machines, pairs
    nothing; a guest left over is paired by one of its addresses in
    `details` (`Machine.pve_guest_details`) when exactly one machine is
    reached at it."""
    machines = list(machines)
    by_name: dict[str, list[M]] = {}
    for machine in machines:
        if machine.id == host_id:
            continue
        for name in names_of(machine):
            by_name.setdefault(name, []).append(machine)
    guest_names = [_guest_name(g) for g in guests or [] if not g.get("template")]
    paired: dict[int, M] = {}
    for guest in guests or []:
        name = _guest_name(guest)
        vmid = guest.get("vmid")
        if guest.get("template") or not name or not isinstance(vmid, int):
            continue
        candidates = {m.id: m for m in by_name.get(name, [])}
        if len(candidates) == 1 and guest_names.count(name) == 1:
            paired[vmid] = next(iter(candidates.values()))
    if details:
        by_address: dict[str, list[M]] = {}
        for machine in machines:
            address = str(getattr(machine, "ip_address", "") or "").strip().lower()
            if address and machine.id != host_id:
                by_address.setdefault(address, []).append(machine)
        taken = {m.id for m in paired.values()}
        for guest in guests or []:
            vmid = guest.get("vmid")
            if not isinstance(vmid, int) or vmid in paired or guest.get("template"):
                continue
            ips = (details.get(str(vmid)) or {}).get("ips") or []
            found = {m.id: m for ip in ips for m in by_address.get(str(ip).lower(), [])}
            if len(found) == 1:
                machine = next(iter(found.values()))
                if machine.id not in taken:
                    paired[vmid] = machine
                    taken.add(machine.id)
    return paired


async def _hypervisors(db: AsyncSession) -> list[tuple[Machine, list[dict[str, Any]] | None]]:
    result = await db.execute(select(Machine).where(Machine.pve_version.is_not(None)))
    return [(host, host.pve_guests) for host in result.scalars().all()]


async def host_of(db: AsyncSession, machine: Machine) -> GuestHost | None:
    """The managed Proxmox host `machine` runs on, if debcontrol can tell.
    A machine known to be bare metal runs on nothing."""
    if machine.is_physical:
        return None
    return find_host(machine, await _hypervisors(db))


async def visible_host_of(db: AsyncSession, user: User, machine: Machine) -> GuestHost | None:
    """`host_of`, but only a host `user` may see."""
    host = await host_of(db, machine)
    if host is None:
        return None
    query = await machines_visible_to(db, user)
    visible = await db.execute(
        query.with_only_columns(Machine.id).where(Machine.id == host.machine_id)
    )
    return host if visible.first() is not None else None


@dataclass(frozen=True)
class _Row:
    id: uuid.UUID
    name: str
    discovered_hostname: str | None
    ip_address: str | None = None


async def machines_for_guests(db: AsyncSession, user: User, host: Machine) -> dict[int, _Row]:
    """`{vmid: machine}` for the guests of `host` that are machines `user`
    may see."""
    if not host.pve_guests:
        return {}
    query = await machines_visible_to(db, user)
    rows = await db.execute(
        query.with_only_columns(
            Machine.id, Machine.name, Machine.discovered_hostname, Machine.ip_address
        )
    )
    machines = [
        _Row(id=r[0], name=r[1], discovered_hostname=r[2], ip_address=r[3]) for r in rows.all()
    ]
    return pair_guests(host.id, host.pve_guests, machines, host.pve_guest_details)
