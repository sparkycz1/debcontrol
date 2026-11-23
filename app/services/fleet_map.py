"""The fleet as a map (nav: **Map**): what runs where, and which machines
share a network.

**What runs where** (`where`): every Proxmox VE host with its VMs and
containers on that node, each guest linked to the machine it is when
debcontrol manages it (`app.services.proxmox_guest_links`: by name, then
by address), and under every machine its Docker stacks with their
containers and the containers' web links (`app.services.container_links`).
Machines on no visible host stand on their own. Everything links to its
page, so the map is a way in, not only a picture.

**Networks** (`networks`): the machines grouped by the IPv4 networks of
their addresses (facts refresh: `ip -4 addr`, scope global) with each
network's gateway (the default gateway a machine of it reported). Docker
and other container bridges are left out: every Docker host has a
`172.17.0.0/16` of its own, and they are not one network. A machine with
an address on several networks (a router, a multi-homed host) is in each.

Both read only what the database already has and are scoped by the
caller: they are given the machines the account may see.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.db.models.machine import Machine
from app.services import container_links, proxmox_guest_links
from app.ssh import proxmox

# Interfaces whose addresses are no real network of the fleet.
_SKIP_PREFIXES = ("docker", "br-", "veth", "cni", "flannel", "cali", "virbr", "lxcbr", "podman")


@dataclass
class Container:
    name: str
    state: str
    image: str
    links: list[container_links.WebLink]


@dataclass
class Stack:
    name: str  # "" = containers that belong to no Compose project
    containers: list[Container] = field(default_factory=list)

    @property
    def running(self) -> int:
        return sum(1 for c in self.containers if c.state == "running")


@dataclass
class Guest:
    vmid: int
    name: str
    type: str
    status: str
    ips: list[str]
    machine: MachineEntry | None = None


@dataclass
class MachineEntry:
    machine: Machine
    stacks: list[Stack] = field(default_factory=list)
    guests: list[Guest] = field(default_factory=list)
    node: str | None = None

    @property
    def containers(self) -> int:
        return sum(len(s.containers) for s in self.stacks)


def stacks_of(machine: Machine) -> list[Stack]:
    """The machine's containers (latest sample) by Compose project."""
    if machine.docker_status != "ok":
        return []
    stacks: dict[str, Stack] = {}
    for row in machine.docker_containers or []:
        if not isinstance(row, dict) or not row.get("name"):
            continue
        project = str(row.get("compose_project") or "")
        stack = stacks.setdefault(project, Stack(project))
        stack.containers.append(
            Container(
                name=str(row["name"]),
                state=str(row.get("state") or ""),
                image=str(row.get("image") or ""),
                links=container_links.web_links(row, machine.ip_address),
            )
        )
    for stack in stacks.values():
        stack.containers.sort(key=lambda c: c.name.lower())
    return sorted(stacks.values(), key=lambda s: (s.name == "", s.name.lower()))


def _matches(entry: MachineEntry, query: str) -> bool:
    texts = [entry.machine.name, entry.machine.discovered_hostname or ""]
    for stack in entry.stacks:
        texts.append(stack.name)
        texts.extend(c.name for c in stack.containers)
        texts.extend(c.image for c in stack.containers)
    for guest in entry.guests:
        texts.extend([guest.name, str(guest.vmid), *guest.ips])
        if guest.machine is not None and _matches(guest.machine, query):
            return True
    return any(query in text.lower() for text in texts if text)


def where(machines: list[Machine], query: str = "") -> list[MachineEntry]:
    """Proxmox VE hosts first (their guests nested), then every machine on
    no visible host; `query` keeps the ones where a name matches."""
    entries = {m.id: MachineEntry(m, stacks_of(m)) for m in machines if m.is_active}
    nested: set[uuid.UUID] = set()
    hosts: list[MachineEntry] = []
    for entry in entries.values():
        machine = entry.machine
        if machine.pve_guests is None:
            continue
        node = proxmox.local_node(machine.pve_cluster, machine.pve_resources)
        entry.node = node
        paired = proxmox_guest_links.pair_guests(
            machine.id, machine.pve_guests, [e.machine for e in entries.values()],
            machine.pve_guest_details,
        )
        details = machine.pve_guest_details or {}
        for row in machine.pve_guests:
            vmid = row.get("vmid")
            if not isinstance(vmid, int) or row.get("template"):
                continue
            if node and row.get("node") and row.get("node") != node:
                continue  # shown under the node it runs on
            found = paired.get(vmid)
            guest = Guest(
                vmid=vmid,
                name=str(row.get("name") or ""),
                type=str(row.get("type") or ""),
                status=str(row.get("status") or ""),
                ips=list((details.get(str(vmid)) or {}).get("ips") or []),
            )
            if found is not None and found.id in entries and found.id != machine.id:
                guest.machine = entries[found.id]
                nested.add(found.id)
            entry.guests.append(guest)
        entry.guests.sort(key=lambda g: g.vmid)
        hosts.append(entry)
    host_ids = {h.machine.id for h in hosts}
    # A host that is itself a guest of another host stays at the top too.
    standalone = [
        e for e in entries.values() if e.machine.id not in nested and e.machine.id not in host_ids
    ]
    hosts.sort(key=lambda e: e.machine.name.lower())
    standalone.sort(key=lambda e: e.machine.name.lower())
    result = hosts + standalone
    query = query.strip().lower()
    if query:
        result = [e for e in result if _matches(e, query)]
    return result


def where_dict(entries: list[MachineEntry]) -> list[dict[str, Any]]:
    """`where` as data for the REST API."""

    def machine_dict(entry: MachineEntry) -> dict[str, Any]:
        return {
            "machine_id": str(entry.machine.id),
            "name": entry.machine.name,
            "node": entry.node,
            "stacks": [
                {
                    "name": stack.name or None,
                    "containers": [
                        {
                            "name": c.name,
                            "state": c.state,
                            "image": c.image,
                            "links": [link.url for link in c.links],
                        }
                        for c in stack.containers
                    ],
                }
                for stack in entry.stacks
            ],
            "guests": [
                {
                    "vmid": g.vmid,
                    "name": g.name,
                    "type": g.type,
                    "status": g.status,
                    "ips": g.ips,
                    "machine": machine_dict(g.machine) if g.machine else None,
                }
                for g in entry.guests
            ],
        }

    return [machine_dict(e) for e in entries]


# --- Networks ---------------------------------------------------------------------


@dataclass
class Member:
    machine: Machine
    address: str
    interface: str


@dataclass
class Network:
    cidr: str
    gateways: list[str] = field(default_factory=list)
    members: list[Member] = field(default_factory=list)

    @property
    def gateway_member(self) -> Member | None:
        """The managed machine that is this network's gateway, if any."""
        return next((m for m in self.members if m.address in self.gateways), None)


def _networks_of(machine: Machine) -> list[tuple[ipaddress.IPv4Network, str, str]]:
    found: list[tuple[ipaddress.IPv4Network, str, str]] = []
    for entry in machine.network_interfaces or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("interface") or "")
        value = str(entry.get("address") or "")
        if not value or name.startswith(_SKIP_PREFIXES):
            continue
        try:
            interface = ipaddress.ip_interface(value)
        except ValueError:
            continue
        if not isinstance(interface, ipaddress.IPv4Interface):
            continue
        if interface.is_loopback or interface.is_link_local:
            continue
        network = interface.network
        if network.prefixlen == 32:
            continue
        found.append((network, str(interface.ip), name))
    return found


def networks(machines: list[Machine]) -> tuple[list[Network], list[Machine]]:
    """(the networks with their machines, biggest first; the machines with
    no known address — facts not refreshed yet)."""
    by_cidr: dict[str, Network] = {}
    unknown: list[Machine] = []
    for machine in machines:
        if not machine.is_active:
            continue
        found = _networks_of(machine)
        if not found:
            unknown.append(machine)
            continue
        for network, address, interface in found:
            entry = by_cidr.setdefault(str(network), Network(str(network)))
            if all(m.machine.id != machine.id for m in entry.members):
                entry.members.append(Member(machine, address, interface))
            gateway = machine.default_gateway
            if gateway and gateway not in entry.gateways:
                try:
                    address_of_gateway = ipaddress.ip_address(gateway)
                except ValueError:
                    address_of_gateway = None
                if isinstance(address_of_gateway, ipaddress.IPv4Address) and (
                    address_of_gateway in network
                ):
                    entry.gateways.append(gateway)
    for entry in by_cidr.values():
        entry.members.sort(key=lambda m: ipaddress.ip_address(m.address))
        entry.gateways.sort()
    ordered = sorted(
        by_cidr.values(),
        key=lambda n: (-len(n.members), ipaddress.ip_network(n.cidr)),
    )
    unknown.sort(key=lambda m: m.name.lower())
    return ordered, unknown


def networks_dict(found: list[Network], unknown: list[Machine]) -> dict[str, Any]:
    """`networks` as data for the REST API."""
    return {
        "networks": [
            {
                "cidr": n.cidr,
                "gateways": n.gateways,
                "machines": [
                    {
                        "machine_id": str(m.machine.id),
                        "name": m.machine.name,
                        "address": m.address,
                        "interface": m.interface,
                        "health_status": m.machine.health_status,
                        "is_reachable": m.machine.is_reachable,
                    }
                    for m in n.members
                ],
            }
            for n in found
        ],
        "unknown": [{"machine_id": str(m.id), "name": m.name} for m in unknown],
    }
