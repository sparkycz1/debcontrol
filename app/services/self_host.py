"""Which managed machines debcontrol itself depends on.

Updating the machine debcontrol runs on can restart Docker, and with it
the worker running the update — and every other update of the same batch.
Updating the hypervisor under it takes the whole VM down. Both are
legitimate things to do, just not in the middle of a batch.

Detection needs no configuration: a container shares its host's kernel,
so `/proc/sys/kernel/random/boot_id` reads the same inside debcontrol's
containers as on the host. Each machine reports its own with its facts
(`Machine.boot_id`); the one that matches is the host. Its hypervisor, if
that is a managed Proxmox host too, comes from
`app.services.proxmox_guest_links`. No match (Docker Desktop's hidden VM,
a host that is not managed) means no warning — never a wrong one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.user import User
from app.services import proxmox_guest_links
from app.services.access_scope import machines_visible_to

_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")

# `MachineUpdateRun.hold_order`: a batch updates these after everything
# else, the host before the hypervisor under it.
HOLD_HOST = 1
HOLD_HYPERVISOR = 2


@lru_cache(maxsize=1)
def own_boot_id() -> str | None:
    """The boot id of the kernel this process runs on; None where there is
    no such file (not Linux)."""
    try:
        value = _BOOT_ID_PATH.read_text(encoding="ascii").strip().lower()
    except (OSError, ValueError):
        return None
    return value or None


@dataclass(frozen=True)
class SelfHost:
    """Machine ids debcontrol depends on."""

    hosts: frozenset[uuid.UUID] = field(default_factory=frozenset)
    hypervisors: frozenset[uuid.UUID] = field(default_factory=frozenset)

    @property
    def ids(self) -> frozenset[uuid.UUID]:
        return self.hosts | self.hypervisors

    def hold_order(self, machine_id: uuid.UUID) -> int | None:
        """Where in a batch this machine belongs — None for "with the rest"."""
        if machine_id in self.hypervisors:
            return HOLD_HYPERVISOR
        if machine_id in self.hosts:
            return HOLD_HOST
        return None

    def role(self, machine_id: uuid.UUID) -> str | None:
        """"host" / "hypervisor" / None, for the warning shown to a person."""
        order = self.hold_order(machine_id)
        if order is None:
            return None
        return "hypervisor" if order == HOLD_HYPERVISOR else "host"


NONE = SelfHost()


async def find(db: AsyncSession) -> SelfHost:
    """The machines debcontrol runs on, among the managed ones."""
    boot_id = own_boot_id()
    if boot_id is None:
        return NONE
    result = await db.execute(select(Machine).where(Machine.boot_id == boot_id))
    hosts = list(result.scalars().all())
    if not hosts:
        return NONE
    hypervisors: set[uuid.UUID] = set()
    for host in hosts:
        above = await proxmox_guest_links.host_of(db, host)
        if above is not None:
            hypervisors.add(above.machine_id)
    return SelfHost(hosts=frozenset(h.id for h in hosts), hypervisors=frozenset(hypervisors))


async def role_of(db: AsyncSession, machine: Machine) -> str | None:
    """`SelfHost.role` for one machine."""
    return (await find(db)).role(machine.id)


async def visible_names(db: AsyncSession, user: User) -> list[str]:
    """Names of the machines debcontrol depends on, among those `user` may
    see — for the note next to a batch update."""
    own = await find(db)
    if not own.ids:
        return []
    query = await machines_visible_to(db, user)
    rows = await db.execute(
        query.with_only_columns(Machine.id, Machine.name).where(Machine.id.in_(own.ids))
    )
    found = sorted(rows.all(), key=lambda row: (own.hold_order(row[0]) or 0, row[1].lower()))
    return [row[1] for row in found]
