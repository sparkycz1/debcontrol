"""A machine's network as a picture: network cards → bonds → bridges and
VLANs → what is plugged into them (Proxmox VE guests, Docker containers,
libvirt VMs), each line as thick as the traffic over it.

Built from what the monitoring sample already reads on any Linux host —
every interface with its kind and the bridge or bond it belongs to
(`Machine.network_links`) and its counters (`live_overview.interface_table`)
— so it works on a plain Debian box with a bridge as much as on a Proxmox
host. Nothing new runs on the machine.

What is plugged in is told by the interface names the hypervisors use:

- Proxmox VE: `tap<vmid>i<n>` (a VM) and `veth<vmid>i<n>` (a container),
  through the firewall bridge `fwbr<vmid>i<n>` when the guest's firewall
  is on (its `fwpr<vmid>p<n>` port is what sits in the real bridge).
- Docker: the `veth…` ports of `docker0` and of `br-<id>` networks,
  counted per bridge rather than drawn one by one.
- Anything else in a bridge (a libvirt `vnet0`, a VPN tap) is drawn under
  its own name.

The picture is laid out here (columns, rows, curves), so the template only
draws it as SVG: no script, no inline style (`stroke-width` is an SVG
attribute, colors come from CSS classes).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from app.db.models.machine import Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.services import live_overview

_GUEST_PORT_RE = re.compile(r"^(tap|veth)(\d+)i(\d+)$")
_FIREWALL_RE = re.compile(r"^fw(br|pr|ln)(\d+)[ip](\d+)$")
_DOCKER_BRIDGE_RE = re.compile(r"^(docker\d*|br-[0-9a-f]{6,})$")

COLUMN_WIDTH = 210
NODE_WIDTH = 160
NODE_HEIGHT = 36
ROW_HEIGHT = 48
PADDING = 8
MAX_ENDPOINTS = 60

# 0 network cards, 1 bonds, 2 bridges / VLANs / other, 3 what is plugged in.
_COLUMN = {"physical": 0, "wireless": 0, "bond": 1, "bridge": 2, "vlan": 2, "virtual": 2}


@dataclass
class TopologyNode:
    id: str
    kind: str  # physical, wireless, bond, bridge, vlan, virtual, guest, docker, port
    label: str
    detail: str = ""
    up: bool = True
    rate: float | None = None
    href: str | None = None
    column: int = 0
    x: int = 0
    y: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "detail": self.detail,
            "up": self.up,
            "rate": self.rate,
            "href": self.href,
        }


@dataclass
class TopologyEdge:
    source: str
    target: str
    rate: float | None
    width: float = 1.5
    path: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"from": self.source, "to": self.target, "rate": self.rate}


@dataclass
class Topology:
    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)
    width: int = 0
    height: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.as_dict() for n in self.nodes],
            "edges": [e.as_dict() for e in self.edges],
        }


def _rate(link: dict[str, Any]) -> float | None:
    values = [v for v in (link.get("rx"), link.get("tx")) if isinstance(v, (int, float))]
    return float(sum(values)) if values else None


def _add(a: float | None, b: float | None) -> float | None:
    if a is None:
        return b
    if b is None:
        return a
    return a + b


def line_width(rate: float | None) -> float:
    """1.5 for an idle line, up to 8 for about 1 GB/s."""
    if not rate or rate <= 0:
        return 1.5
    return round(1.5 + 6.5 * min(1.0, math.log10(1 + rate / 1000) / 6), 1)


def _firewall_uplinks(by_name: dict[str, dict[str, Any]]) -> dict[tuple[str, str], str]:
    """(vmid, card) -> the bridge its firewall port `fwpr<vmid>p<card>` is in."""
    found: dict[tuple[str, str], str] = {}
    for name, link in by_name.items():
        match = _FIREWALL_RE.match(name)
        if match and match.group(1) == "pr" and link.get("master"):
            found[(match.group(2), match.group(3))] = str(link["master"])
    return found


def build(
    links: list[dict[str, Any]],
    guests: list[dict[str, Any]] | None = None,
    *,
    guest_href: str | None = None,
    docker_href: str | None = None,
) -> Topology | None:
    """The picture for one machine, from `interface_table`'s rows (each
    {"name", "kind", "state", "master", "addresses", "speed_mbps", "rx",
    "tx"}). None when there is nothing to draw beyond single cards: no
    bridge and no bond. `guest_href` is a format string with `{vmid}`."""
    by_name = {str(link.get("name")): link for link in links if link.get("name")}
    if not any(link.get("kind") in ("bridge", "bond") for link in by_name.values()):
        return None
    names = {g.get("vmid"): str(g.get("name") or "") for g in guests or []}
    types = {g.get("vmid"): str(g.get("type") or "") for g in guests or []}

    topo = Topology()
    nodes: dict[str, TopologyNode] = {}
    # The real bridge behind each Proxmox firewall bridge: fwbr101i0 holds
    # tap101i0 and fwln101i0, while fwpr101p0 sits in vmbr0.
    firewall_uplink = _firewall_uplinks(by_name)

    def bridge_of(master: str) -> str:
        match = _FIREWALL_RE.match(master)
        if match and match.group(1) == "br":
            return firewall_uplink.get((match.group(2), match.group(3)), master)
        return master

    endpoints: dict[str, TopologyNode] = {}
    edges: dict[tuple[str, str], TopologyEdge] = {}

    def connect(source: str, target: str, rate: float | None) -> None:
        edge = edges.get((source, target))
        if edge is None:
            edges[(source, target)] = TopologyEdge(source, target, rate)
        else:
            edge.rate = _add(edge.rate, rate)

    for name, link in sorted(by_name.items()):
        kind = str(link.get("kind") or "virtual")
        if _FIREWALL_RE.match(name):
            continue
        master = str(link.get("master") or "")
        guest = _GUEST_PORT_RE.match(name)
        if guest and master:
            vmid = int(guest.group(2))
            bridge = bridge_of(master)
            key = f"guest:{vmid}:{bridge}"
            node = endpoints.get(key)
            if node is None:
                label = names.get(vmid) or str(vmid)
                guest_type = types.get(vmid) or ("lxc" if guest.group(1) == "veth" else "qemu")
                node = TopologyNode(
                    id=key,
                    kind="guest",
                    label=label,
                    detail=f"{'CT' if guest_type == 'lxc' else 'VM'} {vmid}",
                    href=guest_href.format(vmid=vmid) if guest_href else None,
                    column=3,
                )
                endpoints[key] = node
            node.rate = _add(node.rate, _rate(link))
            node.up = node.up and link.get("state") != "down"
            connect(key, bridge, _rate(link))
            continue
        if master and _DOCKER_BRIDGE_RE.match(master) and name.startswith("veth"):
            key = f"docker:{master}"
            node = endpoints.get(key)
            if node is None:
                node = TopologyNode(
                    id=key, kind="docker", label="Docker", detail="0",
                    href=docker_href, column=3,
                )
                endpoints[key] = node
            node.detail = str(int(node.detail) + 1)
            node.rate = _add(node.rate, _rate(link))
            connect(key, master, _rate(link))
            continue
        if kind == "virtual" and master and by_name.get(master, {}).get("kind") == "bridge":
            key = f"port:{name}"
            endpoints[key] = TopologyNode(
                id=key, kind="port", label=name, rate=_rate(link),
                up=link.get("state") != "down", column=3,
            )
            connect(key, master, _rate(link))
            continue
        if kind == "virtual" and (name.startswith("veth") or master):
            # The host end of something we can't name, inside a non-bridge.
            continue
        addresses = [str(a) for a in link.get("addresses") or []]
        speed = link.get("speed_mbps")
        detail = addresses[0] if addresses else ""
        if not detail and isinstance(speed, int):
            detail = f"{speed / 1000:g} Gbit/s" if speed >= 1000 else f"{speed} Mbit/s"
        nodes[name] = TopologyNode(
            id=name,
            kind=kind,
            label=name,
            detail=detail,
            up=link.get("state") != "down",
            rate=_rate(link),
            column=_COLUMN.get(kind, 2),
        )
        if master:
            connect(name, bridge_of(master), _rate(link))
        elif kind == "vlan" and "." in name:
            parent = name.rsplit(".", 1)[0]
            if parent in by_name:
                connect(name, parent, _rate(link))

    ordered_endpoints = sorted(
        endpoints.values(), key=lambda n: (n.kind != "guest", n.label.lower())
    )[:MAX_ENDPOINTS]
    every = {**nodes, **{n.id: n for n in ordered_endpoints}}
    topo.edges = [e for e in edges.values() if e.source in every and e.target in every]
    linked = {e.source for e in topo.edges} | {e.target for e in topo.edges}
    # Lone virtual interfaces (a VPN, tun) without lines add nothing here.
    topo.nodes = [
        n for n in every.values() if n.id in linked or n.kind in ("physical", "wireless", "bond")
    ]
    _layout(topo)
    return topo


def _layout(topo: Topology) -> None:
    columns = sorted({n.column for n in topo.nodes})
    position = {column: index for index, column in enumerate(columns)}
    targets: dict[str, list[str]] = {}
    for edge in topo.edges:
        targets.setdefault(edge.source, []).append(edge.target)
    # Rows: bridges and bonds in name order, then each column ordered by
    # the row of what it connects to, so lines cross as little as can be.
    rows: dict[str, float] = {}
    by_column: dict[int, list[TopologyNode]] = {}
    for node in topo.nodes:
        by_column.setdefault(node.column, []).append(node)
    for column in (2, 1, 3, 0):
        members = by_column.get(column, [])
        if column == 2:
            members.sort(key=lambda n: (n.kind not in ("bridge",), n.label))
        else:
            def anchor(node: TopologyNode) -> tuple[float, str]:
                linked = [rows[t] for t in targets.get(node.id, []) if t in rows]
                linked += [
                    rows[e.source] for e in topo.edges if e.target == node.id and e.source in rows
                ]
                return (sum(linked) / len(linked) if linked else 1e9, node.label)

            members.sort(key=anchor)
        for index, node in enumerate(members):
            rows[node.id] = index
    height_rows = max((len(m) for m in by_column.values()), default=1)
    for node in topo.nodes:
        members = by_column[node.column]
        offset = (height_rows - len(members)) * ROW_HEIGHT / 2
        node.x = PADDING + position[node.column] * COLUMN_WIDTH
        node.y = int(PADDING + offset + members.index(node) * ROW_HEIGHT)
    topo.width = PADDING * 2 + (len(columns) - 1) * COLUMN_WIDTH + NODE_WIDTH
    topo.height = PADDING * 2 + height_rows * ROW_HEIGHT - (ROW_HEIGHT - NODE_HEIGHT)
    placed = {n.id: n for n in topo.nodes}
    for edge in topo.edges:
        a, b = placed[edge.source], placed[edge.target]
        left, right = (a, b) if a.x <= b.x else (b, a)
        x1 = left.x + NODE_WIDTH
        y1 = left.y + NODE_HEIGHT // 2
        x2 = right.x
        y2 = right.y + NODE_HEIGHT // 2
        if x1 > x2:  # same column: loop out to the right
            x1, x2 = left.x + NODE_WIDTH, right.x + NODE_WIDTH
            bend = x1 + 40
            edge.path = f"M{x1},{y1} C{bend},{y1} {bend},{y2} {x2},{y2}"
        else:
            middle = (x1 + x2) // 2
            edge.path = f"M{x1},{y1} C{middle},{y1} {middle},{y2} {x2},{y2}"
        edge.width = line_width(edge.rate)


def of_machine(
    machine: Machine,
    newest: MachineMonitoringSample | None,
    previous: MachineMonitoringSample | None,
    *,
    with_links: bool = True,
) -> Topology | None:
    """`build` for a machine from its two newest monitoring samples (see
    `live_overview.load_recent`), linking guests to their page and Docker
    to the Docker tab when `with_links`."""
    links = [
        link
        for group in live_overview.interface_table(machine, newest, previous)
        for link in group["links"]
    ]
    base = f"/machines/{machine.id}"
    return build(
        links,
        machine.pve_guests,
        guest_href=f"{base}/proxmox/guests/{{vmid}}" if with_links else None,
        docker_href=f"{base}/docker" if with_links else None,
    )
