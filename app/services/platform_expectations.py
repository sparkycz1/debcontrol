"""What is normal for a kind of machine, so it is not reported as a problem.

- **Containers** (LXC, OpenVZ, systemd-nspawn, ... — `Machine.virtualization`
  from `systemd-detect-virt`): a container may not mount the kernel's own
  filesystems or load modules, so units such as `sys-kernel-config.mount`
  or `systemd-modules-load.service` fail in every one of them. They are
  left out of the failed services (`filter_failed_units`), and so out of
  health, notifications and the counts.
- **Security audit** (`expected_audit_keys`): a Proxmox VE node or any
  machine with bridges runs its bridged interfaces in promiscuous mode
  (that is how a bridge works — Lynis NETW-3015); a machine with only
  private addresses is not reachable from the internet, so "no firewall
  rules" (Lynis FIRE-*, the firewall / intrusion-prevention checks) is not
  a finding there. These count like findings marked OK, and the Security
  tab lists them apart with the reason.

Pure functions over a machine's stored facts.
"""

from __future__ import annotations

import ipaddress
from typing import Any

# systemd-detect-virt's names for container technologies.
CONTAINERS = frozenset(
    {"lxc", "lxc-libvirt", "openvz", "systemd-nspawn", "docker", "podman", "rkt", "wsl",
     "proot", "pouch"}
)

# Units that fail in an (unprivileged) container by design.
CONTAINER_NORMAL_FAILURES = frozenset(
    {
        "sys-kernel-config.mount",
        "sys-kernel-debug.mount",
        "sys-kernel-tracing.mount",
        "sys-fs-fuse-connections.mount",
        "proc-sys-fs-binfmt_misc.mount",
        "proc-sys-fs-binfmt_misc.automount",
        "systemd-binfmt.service",
        "systemd-modules-load.service",
        "systemd-remount-fs.service",
        "systemd-sysctl.service",
        "systemd-journald-audit.socket",
        "systemd-udevd.service",
        "systemd-udev-trigger.service",
        "systemd-udevd-kernel.socket",
        "systemd-udevd-control.socket",
        "systemd-hwdb-update.service",
        "kmod-static-nodes.service",
        "dev-hugepages.mount",
        "dev-mqueue.mount",
    }
)

PROMISCUOUS_TEST = "NETW-3015"
FIREWALL_TEST_PREFIX = "FIRE-"
FIREWALL_CHECKS = frozenset({"firewall", "intrusion_prevention", "fail2ban_ssh_port"})

REASON_BRIDGES = "bridges"
REASON_PRIVATE = "private_network"

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_container(machine: Any) -> bool:
    return str(getattr(machine, "virtualization", None) or "").lower() in CONTAINERS


def filter_failed_units(machine: Any, units: list[str] | None) -> list[str] | None:
    """`units` without the ones that fail in every container (only on a
    container); None stays None ("couldn't tell")."""
    if units is None or not is_container(machine):
        return units
    return [u for u in units if u not in CONTAINER_NORMAL_FAILURES]


def _addresses(machine: Any) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    found: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for entry in getattr(machine, "network_interfaces", None) or []:
        if not isinstance(entry, dict):
            continue
        text = str(entry.get("address") or "").split("/", 1)[0].split("%", 1)[0]
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            continue
        if not address.is_loopback:
            found.append(address)
    return found


def only_private_addresses(machine: Any) -> bool:
    """Every IPv4 address of the machine is private (RFC 1918, CGNAT,
    link-local) — IPv6 is judged only when it has no IPv4 at all, since a
    LAN host's global IPv6 address is normally behind the router's own
    firewall. False when nothing is known."""
    addresses = _addresses(machine)
    v4 = [a for a in addresses if a.version == 4]
    if v4:
        return all(a.is_private or a in _CGNAT or a.is_link_local for a in v4)
    return bool(addresses) and all(not a.is_global for a in addresses)


def has_bridges(machine: Any) -> bool:
    if getattr(machine, "pve_version", None):
        return True
    return any(
        isinstance(link, dict) and link.get("kind") == "bridge"
        for link in getattr(machine, "network_links", None) or []
    )


def expected_audit_keys(machine: Any, audit: Any) -> dict[str, str]:
    """`{finding key: reason}` for the findings of `audit` that are normal
    on `machine` (see the module docstring)."""
    # Imported here: security_audit imports this module.
    from app.services.security_audit import CHECK, LYNIS, finding_key
    from app.ssh.security_checks import FINDING_STATUSES

    if audit is None:
        return {}
    private = only_private_addresses(machine)
    bridges = has_bridges(machine)
    expected: dict[str, str] = {}
    for name in ("warnings", "suggestions"):
        for finding in getattr(audit, name, None) or []:
            if not isinstance(finding, dict):
                continue
            test = str(finding.get("test") or "").upper()
            if test == PROMISCUOUS_TEST and bridges:
                expected[finding_key(LYNIS, finding)] = REASON_BRIDGES
            elif test.startswith(FIREWALL_TEST_PREFIX) and private:
                expected[finding_key(LYNIS, finding)] = REASON_PRIVATE
    if private:
        for check in getattr(audit, "checks", None) or []:
            if (
                isinstance(check, dict)
                and check.get("id") in FIREWALL_CHECKS
                and check.get("status") in FINDING_STATUSES
            ):
                expected[finding_key(CHECK, check)] = REASON_PRIVATE
    return expected
