"""Waking a machine that is switched off (Wake-on-LAN).

A magic packet only travels within one network segment, and debcontrol
itself sits in a container that cannot broadcast onto the machines'
network. So the packet is sent *by another managed machine on the same
network* — the relay: one whose own address lies in the same subnet as
the machine to wake, that is reachable right now and has a confirmed host
key. Nothing to configure; where no such machine exists, waking is simply
not offered.

The machine's network card addresses come from its facts
(`Machine.mac_addresses`), so it must have been seen running once. The
card and firmware have to be set up for Wake-on-LAN — debcontrol cannot
tell whether they are, only send the packet.
"""

from __future__ import annotations

import ipaddress
import shlex
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.ssh.wake import MAC_RE

_MAX_RELAY_CANDIDATES = 500

# Sends the packet to the limited broadcast address and to each subnet's
# own. Plain UDP: no root, nothing to install where python3 is present;
# `wakeonlan` / `etherwake` as fallbacks.
_SENDER = (
    "import socket,sys\n"
    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
    "s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)\n"
    "t=[a for a in sys.argv[1:] if '.' in a]\n"
    "for m in [a for a in sys.argv[1:] if ':' in a]:\n"
    " p=b'\\xff'*6+bytes.fromhex(m.replace(':',''))*16\n"
    " for a in t:\n"
    "  for port in (9,7):\n"
    "   s.sendto(p,(a,port))\n"
)

NO_TOOL_MARKER = "@@NOWAKETOOL"


def _networks(interfaces: list[dict[str, Any]] | None) -> list[ipaddress.IPv4Network]:
    networks = []
    for item in interfaces or []:
        try:
            network = ipaddress.ip_interface(str(item.get("address") or "")).network
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network) and network.prefixlen >= 16:
            networks.append(network)
    return networks


def _address(machine: Any) -> ipaddress.IPv4Address | None:
    try:
        address = ipaddress.ip_address(str(machine.ip_address))
    except ValueError:
        return None
    return address if isinstance(address, ipaddress.IPv4Address) else None


def shared_network(target: Any, relay: Any) -> ipaddress.IPv4Network | None:
    """The network of `relay` that `target`'s address lies in, if any."""
    address = _address(target)
    if address is None:
        return None
    for network in _networks(relay.network_interfaces):
        if address in network:
            return network
    return None


@dataclass(frozen=True)
class WakePlan:
    """How a machine would be woken: by whom, with which addresses."""

    relay_id: uuid.UUID
    relay_name: str
    macs: tuple[str, ...]
    broadcasts: tuple[str, ...]


def macs_of(machine: Any) -> tuple[str, ...]:
    return tuple(
        str(item.get("mac"))
        for item in (machine.mac_addresses or [])
        if isinstance(item, dict) and MAC_RE.match(str(item.get("mac") or ""))
    )


def choose_relay(target: Any, candidates: list[Any]) -> WakePlan | None:
    """The relay for `target` among `candidates`, or None: the machine has
    no known network card, or nothing reachable shares its network."""
    macs = macs_of(target)
    if not macs:
        return None
    for relay in sorted(candidates, key=lambda m: str(m.name).lower()):
        if relay.id == target.id or not relay.is_reachable or not relay.host_key_fingerprint:
            continue
        network = shared_network(target, relay)
        if network is None:
            continue
        return WakePlan(
            relay_id=relay.id,
            relay_name=relay.name,
            macs=macs,
            broadcasts=("255.255.255.255", str(network.broadcast_address)),
        )
    return None


async def plan_for(db: AsyncSession, machine: Machine) -> WakePlan | None:
    """`choose_relay` among every reachable managed machine. Not limited
    to what one account may see: the relay only forwards a packet, and
    which machine does it is not something the person chooses."""
    if not macs_of(machine):
        return None
    result = await db.execute(
        select(Machine)
        .where(
            Machine.is_reachable.is_(True),
            Machine.host_key_fingerprint.is_not(None),
            Machine.id != machine.id,
        )
        .order_by(Machine.name)
        .limit(_MAX_RELAY_CANDIDATES)
    )
    return choose_relay(machine, list(result.scalars().all()))


def build_command(plan: WakePlan) -> str:
    """What the relay runs. Every argument is a checked MAC or IPv4
    address and is quoted all the same."""
    for mac in plan.macs:
        if not MAC_RE.match(mac):
            raise ValueError("Not a MAC address.")
    for broadcast in plan.broadcasts:
        ipaddress.IPv4Address(broadcast)
    arguments = " ".join(shlex.quote(value) for value in (*plan.macs, *plan.broadcasts))
    macs = " ".join(shlex.quote(mac) for mac in plan.macs)
    return (
        "if command -v python3 >/dev/null 2>&1; then "
        f"python3 -c {shlex.quote(_SENDER)} {arguments}; "
        "elif command -v wakeonlan >/dev/null 2>&1; then "
        f'for m in {macs}; do wakeonlan "$m" >/dev/null; done; '
        "elif command -v etherwake >/dev/null 2>&1; then "
        f'for m in {macs}; do sudo -n etherwake "$m"; done; '
        f"else echo {NO_TOOL_MARKER}; exit 3; fi"
    )
