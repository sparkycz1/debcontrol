"""How full each Proxmox VE node is, and where a new guest fits.

Read from what the monitoring sample already keeps — the cluster's nodes
and storages (`Machine.pve_resources`) and its guests (`Machine.pve_guests`),
both from `pvesh get /cluster/resources` — so nothing new runs on a host.

Per node:

- **CPU**: cores, the vCPUs given to its running guests (and to all of
  them), so the over-subscription ratio.
- **Memory**: physical memory, what is in use, and the memory given to its
  running guests (and to all of them). Running guests given more than the
  node has is **over-committed**: they can't all use what they were given
  at once. That is a health warning on the node's own machine
  (`app.services.machine_health`).
- **Storage**: the storages that can hold guest disks (`images` or
  `rootdir` content) with their free space.

Every node of a cluster reports the whole cluster, so a cluster is shown
once (from its most recently sampled machine), keyed by its name; a
standalone host is its own "cluster".

**Where a new guest fits** (`fits`): a node fits a guest of N cores, M
bytes of memory and D bytes of disk when it is online, has at least N
cores, the memory not yet given to its running guests is at least M, and
one of its guest storages has D free. The best fit leaves the most memory
free.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.db.models.machine import Machine
from app.ssh import proxmox

GUEST_CONTENT = ("images", "rootdir")


@dataclass
class NodeStorage:
    name: str
    type: str
    shared: bool
    used_bytes: int | None
    total_bytes: int | None

    @property
    def free_bytes(self) -> int | None:
        if self.total_bytes is None or self.used_bytes is None:
            return None
        return max(self.total_bytes - self.used_bytes, 0)

    @property
    def used_percent(self) -> float | None:
        if not self.total_bytes or self.used_bytes is None:
            return None
        return round(self.used_bytes / self.total_bytes * 100, 1)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "shared": self.shared,
            "used_bytes": self.used_bytes,
            "total_bytes": self.total_bytes,
            "free_bytes": self.free_bytes,
        }


@dataclass
class NodeCapacity:
    """One Proxmox VE node and what is allocated on it."""

    cluster: str | None
    node: str
    online: bool
    cpu_percent: float | None
    cores: int | None
    mem_used_bytes: int | None
    mem_total_bytes: int | None
    guests_running: int = 0
    guests_total: int = 0
    vcpus_running: int = 0
    vcpus_total: int = 0
    mem_running_bytes: int = 0
    mem_total_given_bytes: int = 0
    storages: list[NodeStorage] = field(default_factory=list)
    machine_id: uuid.UUID | None = None
    machine_name: str | None = None

    @property
    def vcpu_ratio(self) -> float | None:
        return round(self.vcpus_running / self.cores, 2) if self.cores else None

    @property
    def mem_given_percent(self) -> float | None:
        if not self.mem_total_bytes:
            return None
        return round(self.mem_running_bytes / self.mem_total_bytes * 100, 1)

    @property
    def mem_used_percent(self) -> float | None:
        if not self.mem_total_bytes or self.mem_used_bytes is None:
            return None
        return round(self.mem_used_bytes / self.mem_total_bytes * 100, 1)

    @property
    def overcommitted(self) -> bool:
        """Running guests were given more memory than the node has."""
        return bool(self.mem_total_bytes) and self.mem_running_bytes > (self.mem_total_bytes or 0)

    @property
    def mem_free_to_give_bytes(self) -> int | None:
        if self.mem_total_bytes is None:
            return None
        return max(self.mem_total_bytes - self.mem_running_bytes, 0)

    @property
    def storage_free_bytes(self) -> int | None:
        free = [s.free_bytes for s in self.storages if s.free_bytes is not None]
        return max(free) if free else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster": self.cluster,
            "node": self.node,
            "online": self.online,
            "machine_id": str(self.machine_id) if self.machine_id else None,
            "machine_name": self.machine_name,
            "cpu_percent": self.cpu_percent,
            "cores": self.cores,
            "vcpus_running": self.vcpus_running,
            "vcpus_total": self.vcpus_total,
            "vcpu_ratio": self.vcpu_ratio,
            "mem_used_bytes": self.mem_used_bytes,
            "mem_total_bytes": self.mem_total_bytes,
            "mem_running_bytes": self.mem_running_bytes,
            "mem_total_given_bytes": self.mem_total_given_bytes,
            "mem_free_to_give_bytes": self.mem_free_to_give_bytes,
            "overcommitted": self.overcommitted,
            "guests_running": self.guests_running,
            "guests_total": self.guests_total,
            "storages": [s.as_dict() for s in self.storages],
            "storage_free_bytes": self.storage_free_bytes,
        }


def nodes_of(
    resources: dict[str, Any] | None,
    guests: list[dict[str, Any]] | None,
    cluster: str | None = None,
) -> list[NodeCapacity]:
    """Every node in one host's `pve_resources`, with its guests counted."""
    nodes: dict[str, NodeCapacity] = {}
    for row in (resources or {}).get("nodes") or []:
        name = str(row.get("node") or "")
        if not name:
            continue
        nodes[name] = NodeCapacity(
            cluster=cluster,
            node=name,
            online=row.get("status") == "online",
            cpu_percent=row.get("cpu_percent"),
            cores=row.get("cores"),
            mem_used_bytes=row.get("mem_bytes"),
            mem_total_bytes=row.get("maxmem_bytes"),
        )
    for guest in guests or []:
        node = nodes.get(str(guest.get("node") or ""))
        if node is None or guest.get("template"):
            continue
        cores_value, memory_value = guest.get("cores"), guest.get("maxmem_bytes")
        cores = cores_value if isinstance(cores_value, int) else 0
        memory = memory_value if isinstance(memory_value, int) else 0
        node.guests_total += 1
        node.vcpus_total += cores
        node.mem_total_given_bytes += memory
        if guest.get("status") == "running":
            node.guests_running += 1
            node.vcpus_running += cores
            node.mem_running_bytes += memory
    for row in (resources or {}).get("storages") or []:
        node = nodes.get(str(row.get("node") or ""))
        content = row.get("content") or []
        if node is None or row.get("status") != "available":
            continue
        if not any(kind in content for kind in GUEST_CONTENT):
            continue
        node.storages.append(
            NodeStorage(
                name=str(row.get("storage") or ""),
                type=str(row.get("type") or ""),
                shared=bool(row.get("shared")),
                used_bytes=row.get("used_bytes"),
                total_bytes=row.get("total_bytes"),
            )
        )
    return sorted(nodes.values(), key=lambda n: n.node)


def local_capacity(machine: Machine) -> NodeCapacity | None:
    """The node this machine itself is, or None (not Proxmox VE, or which
    node it is can't be told)."""
    name = proxmox.local_node(machine.pve_cluster, machine.pve_resources)
    if name is None:
        return None
    cluster = (machine.pve_cluster or {}).get("name")
    return next(
        (n for n in nodes_of(machine.pve_resources, machine.pve_guests, cluster) if n.node == name),
        None,
    )


def _sampled(machine: Machine) -> datetime:
    when = machine.monitoring_updated_at
    if when is None:
        return datetime.min
    return when.replace(tzinfo=None) if when.tzinfo else when


def fleet_nodes(machines: list[Machine]) -> list[NodeCapacity]:
    """Every node of every cluster (or standalone host) among `machines`,
    each cluster once — from its most recently sampled machine — and each
    node linked to the machine that is that node, if it is in `machines`."""
    newest: dict[str, Machine] = {}
    machine_of: dict[tuple[str, str], Machine] = {}
    for machine in machines:
        if not machine.pve_resources:
            continue
        cluster = (machine.pve_cluster or {}).get("name")
        key = f"cluster:{cluster}" if cluster else f"host:{machine.id}"
        if key not in newest or _sampled(machine) > _sampled(newest[key]):
            newest[key] = machine
        local = proxmox.local_node(machine.pve_cluster, machine.pve_resources)
        if local:
            machine_of[(key, local)] = machine
    result: list[NodeCapacity] = []
    for key, machine in newest.items():
        cluster = (machine.pve_cluster or {}).get("name")
        for node in nodes_of(machine.pve_resources, machine.pve_guests, cluster):
            owner = machine_of.get((key, node.node))
            if owner is not None:
                node.machine_id = owner.id
                node.machine_name = owner.name
            result.append(node)
    result.sort(key=lambda n: ((n.cluster or "").lower(), n.node.lower()))
    return result


@dataclass(frozen=True)
class Fit:
    node: NodeCapacity
    fits: bool
    reasons: tuple[str, ...]
    mem_left_bytes: int | None


def fits(
    nodes: list[NodeCapacity], cores: int, memory_bytes: int, disk_bytes: int
) -> list[Fit]:
    """Every node with whether a new guest of that size fits and, if not,
    why (`offline`, `cores`, `memory`, `storage`) — the ones that fit
    first, the one leaving the most memory free on top."""
    result: list[Fit] = []
    for node in nodes:
        reasons: list[str] = []
        if not node.online:
            reasons.append("offline")
        if cores and (node.cores or 0) < cores:
            reasons.append("cores")
        free_memory = node.mem_free_to_give_bytes
        if memory_bytes and (free_memory is None or free_memory < memory_bytes):
            reasons.append("memory")
        free_disk = node.storage_free_bytes
        if disk_bytes and (free_disk is None or free_disk < disk_bytes):
            reasons.append("storage")
        left = free_memory - memory_bytes if free_memory is not None else None
        result.append(Fit(node, not reasons, tuple(reasons), left))
    result.sort(key=lambda f: (not f.fits, -(f.mem_left_bytes or 0), f.node.node))
    return result
