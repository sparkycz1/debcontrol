"""Reading a machine's network card addresses from its facts (the MACS
section) — what a Wake-on-LAN packet is addressed to; see
`app.services.wake_on_lan`."""

from __future__ import annotations

import re

MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")
_MAX_MACS = 8


def parse_mac_addresses(section: str) -> list[dict[str, str]]:
    """`[{"interface", "mac"}]` from the facts' `<interface> <mac>` lines:
    real network cards only (the facts command lists those), no all-zero
    or broadcast address."""
    found: list[dict[str, str]] = []
    for line in section.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        interface, mac = parts[0], parts[1].lower()
        if not _IFACE_RE.match(interface) or not MAC_RE.match(mac):
            continue
        if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            continue
        if all(item["mac"] != mac for item in found):
            found.append({"interface": interface, "mac": mac})
    return found[:_MAX_MACS]
