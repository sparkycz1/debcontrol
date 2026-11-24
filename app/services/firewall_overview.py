"""The fleet's firewall picture (Security → Firewall and its REST
equivalent): each machine's `app.ssh.firewall.overview`, ordered so the
unprotected machines come first, and the newest Fail2Ban bans across the
fleet."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.db.models.machine import Machine
from app.ssh import firewall


@dataclass(frozen=True)
class FirewallRow:
    machine: Machine
    view: dict[str, Any]


PROTECTION_ORDER = {"off": 0, "unknown": 1, "on": 2}


def firewall_rows(machines: list[Machine]) -> list[FirewallRow]:
    """Every machine with its firewall overview: unprotected first, then
    unknown, then protected; most bans first within each."""
    rows = [FirewallRow(m, firewall.overview(m.firewall, m.fail2ban)) for m in machines]
    rows.sort(
        key=lambda r: (
            PROTECTION_ORDER.get(r.view["protection"], 1),
            -int(r.view["fail2ban"]["currently_banned"]),
            r.machine.name.lower(),
        )
    )
    return rows


def fleet_recent_bans(machines: list[Machine], limit: int = 50) -> list[dict[str, Any]]:
    """The newest current Fail2Ban bans across the machines."""
    bans = [
        {**ban, "machine": m}
        for m in machines
        for ban in firewall.recent_bans(m.fail2ban, limit)
    ]
    bans.sort(key=lambda b: b.get("since") or "", reverse=True)
    return bans[:limit]
