"""A read-only look at a machine's packet filter and Fail2Ban — the
machine's Security tab, the fleet's Security → Firewall page and
`GET /api/v1/machines/{id}/firewall`.

Gathered with the facts (hourly), as two extra sections of
`app.ssh.facts.FACTS_COMMAND`. debcontrol never changes a rule here.

- **FIREWALL** — which of nftables, ufw, firewalld and the Proxmox VE
  firewall are running (`systemctl is-active`), plus:
  - the nftables ruleset as JSON (`nft -j list ruleset`, root) — reduced
    here to tables, chains, rule counts and the input hook's policy; the
    rules themselves are not stored;
  - ufw's state (`ufw status verbose`, root; without the grant just
    `ENABLED=` from the world-readable `/etc/ufw/ufw.conf`);
  - the Proxmox VE firewall options of the cluster and this node
    (`pvesh`, already granted for the Proxmox pages).
- **FAIL2BAN** — when `fail2ban-client` exists: every jail's failed and
  banned counts and its current bans with their start times (`get <jail>
  banip --with-time`, Fail2Ban 0.11+). Needs root; the onboarding sudoers
  grant allows only these read commands (`status`, `status <jail>`,
  `get <jail> banip --with-time`) — never `set`, `unban` or `reload`.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

FIREWALL_MARKER = "FIREWALL"
FAIL2BAN_MARKER = "FAIL2BAN"
MARKERS = (FIREWALL_MARKER, FAIL2BAN_MARKER)

UNITS = ("nftables", "ufw", "firewalld", "pve-firewall")
MAX_TABLES = 64
MAX_UFW_RULES = 100
MAX_JAILS = 32
MAX_BANS_PER_JAIL = 50
# The nft JSON of a big Docker / Kubernetes host can be large; this is
# far beyond any homelab's and still bounded.
MAX_NFT_BYTES = 4_000_000

FIREWALL_SECTION = (
    f"echo ==={FIREWALL_MARKER}===; "
    f"for u in {' '.join(UNITS)}; do "
    "echo \"@@UNIT $u $(systemctl is-active \"$u\" 2>/dev/null)\"; done; "
    "if command -v nft >/dev/null 2>&1; then echo @@NFT; "
    "(sudo -n nft -j list ruleset 2>/dev/null || nft -j list ruleset 2>/dev/null) "
    f"| head -c {MAX_NFT_BYTES}; "
    "echo; fi; "
    "if command -v ufw >/dev/null 2>&1; then echo @@UFWCONF; "
    "grep -m1 '^ENABLED=' /etc/ufw/ufw.conf 2>/dev/null; echo @@UFW; "
    "sudo -n ufw status verbose 2>/dev/null || ufw status verbose 2>/dev/null; fi; "
    "if command -v pvesh >/dev/null 2>&1; then echo @@PVECLUSTER; "
    "sudo -n pvesh get /cluster/firewall/options --output-format json 2>/dev/null; echo; "
    "echo @@PVENODE; "
    "sudo -n pvesh get \"/nodes/$(hostname)/firewall/options\" --output-format json 2>/dev/null; "
    "echo; fi"
)

FAIL2BAN_SECTION = (
    f"echo ==={FAIL2BAN_MARKER}===; "
    "if command -v fail2ban-client >/dev/null 2>&1; then "
    "echo \"@@UNIT $(systemctl is-active fail2ban 2>/dev/null)\"; "
    "S=\"$(sudo -n fail2ban-client status 2>/dev/null || fail2ban-client status 2>/dev/null)\"; "
    "if [ -n \"$S\" ]; then echo @@OK; "
    "for j in $(printf '%s\\n' \"$S\" | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do "
    "echo \"@@JAIL $j\"; "
    "sudo -n fail2ban-client status \"$j\" 2>/dev/null "
    "|| fail2ban-client status \"$j\" 2>/dev/null; "
    "echo @@BANS; "
    "sudo -n fail2ban-client get \"$j\" banip --with-time 2>/dev/null "
    "|| fail2ban-client get \"$j\" banip --with-time 2>/dev/null; "
    "done; fi; fi"
)

FACTS_SECTIONS = f"{FIREWALL_SECTION}; {FAIL2BAN_SECTION}"

_JAIL_NAME_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,64}$")
_COUNT_RE = re.compile(r"(Currently failed|Total failed|Currently banned|Total banned):\s*(\d+)")
_BAN_RE = re.compile(
    r"^(\S+)\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*\+\s*(-?\d+)\s*=\s*"
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})?"
)
_IP_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}(?:/\d{1,3})?$")


def _blocks(section: str) -> dict[str, str]:
    """`@@NAME` lines split the section; the text after each, by name."""
    blocks: dict[str, str] = {}
    current: str | None = None
    lines: list[str] = []
    for line in section.splitlines():
        if line.startswith("@@") and line[2:].strip().isupper() and " " not in line.strip():
            if current is not None:
                blocks[current] = "\n".join(lines).strip()
            current, lines = line[2:].strip(), []
        elif current is not None:
            lines.append(line)
    if current is not None:
        blocks[current] = "\n".join(lines).strip()
    return blocks


def _units(section: str) -> dict[str, str]:
    units: dict[str, str] = {}
    for line in section.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "@@UNIT" and parts[1] in UNITS:
            units[parts[1]] = parts[2] if len(parts) > 2 else "unknown"
    return units


def parse_nft(text: str) -> dict[str, Any] | None:
    """Tables with their chain/rule counts and the input hook's policy;
    None when the ruleset could not be read (no root grant)."""
    try:
        data = json.loads(text) if text.strip() else None
    except ValueError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        return None
    tables: dict[tuple[str, str], dict[str, Any]] = {}
    input_chains: list[dict[str, Any]] = []
    chain_rules: dict[tuple[str, str, str], int] = {}
    for item in data["nftables"]:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("table"), dict):
            t = item["table"]
            key = (str(t.get("family")), str(t.get("name")))
            tables.setdefault(key, {"family": key[0], "name": key[1], "chains": 0, "rules": 0})
        elif isinstance(item.get("chain"), dict):
            c = item["chain"]
            key = (str(c.get("family")), str(c.get("table")))
            table = tables.setdefault(
                key, {"family": key[0], "name": key[1], "chains": 0, "rules": 0}
            )
            table["chains"] += 1
            if c.get("hook") == "input":
                input_chains.append(
                    {
                        "family": key[0],
                        "table": key[1],
                        "chain": str(c.get("name")),
                        "policy": str(c.get("policy") or "accept"),
                    }
                )
        elif isinstance(item.get("rule"), dict):
            r = item["rule"]
            key = (str(r.get("family")), str(r.get("table")))
            table = tables.setdefault(
                key, {"family": key[0], "name": key[1], "chains": 0, "rules": 0}
            )
            table["rules"] += 1
            chain_key = (key[0], key[1], str(r.get("chain")))
            chain_rules[chain_key] = chain_rules.get(chain_key, 0) + 1
    for chain in input_chains:
        chain["rules"] = chain_rules.get((chain["family"], chain["table"], chain["chain"]), 0)
    return {
        "tables": sorted(tables.values(), key=lambda t: (t["family"], t["name"]))[:MAX_TABLES],
        "input_chains": input_chains[:MAX_TABLES],
        "rules": sum(t["rules"] for t in tables.values()),
    }


def parse_ufw(conf: str | None, status: str | None) -> dict[str, Any] | None:
    """`{"active", "defaults", "rules", "readable"}`; None without ufw."""
    if conf is None and status is None:
        return None
    enabled = None
    if conf:
        enabled = conf.split("=", 1)[-1].strip().strip("\"'").lower() == "yes"
    active: bool | None = enabled
    defaults: str | None = None
    rules: list[dict[str, str]] = []
    readable = False
    in_rules = False
    for line in (status or "").splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("status:"):
            readable = True
            active = stripped.split(":", 1)[1].strip().lower() == "active"
        elif stripped.lower().startswith("default:"):
            defaults = stripped.split(":", 1)[1].strip()[:160]
        elif stripped.startswith("--"):
            in_rules = True
        elif in_rules and stripped and len(rules) < MAX_UFW_RULES:
            columns = re.split(r"\s{2,}", stripped)
            if len(columns) >= 3:
                rules.append(
                    {"to": columns[0][:96], "action": columns[1][:32], "from": columns[2][:96]}
                )
    return {"active": active, "defaults": defaults, "rules": rules, "readable": readable}


def _json_dict(text: str | None) -> dict[str, Any] | None:
    try:
        data = json.loads(text) if text and text.strip() else None
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _flag(value: Any, *, default: bool) -> bool:
    text = str(value).strip() if value is not None else ""
    return text == "1" if text in ("0", "1") else default


def parse_firewall_section(section: str) -> dict[str, Any] | None:
    """Everything known about the machine's packet filter, or None when the
    section is missing (an older facts command)."""
    if not section.strip():
        return None
    blocks = _blocks(section)
    units = _units(section)
    nft = parse_nft(blocks["NFT"]) if "NFT" in blocks else None
    ufw = (
        parse_ufw(blocks.get("UFWCONF"), blocks.get("UFW"))
        if "UFWCONF" in blocks or "UFW" in blocks
        else None
    )
    pve: dict[str, Any] | None = None
    if "PVECLUSTER" in blocks or "PVENODE" in blocks:
        cluster = _json_dict(blocks.get("PVECLUSTER"))
        node = _json_dict(blocks.get("PVENODE"))
        if cluster is not None or node is not None:
            pve = {
                "cluster_enabled": _flag((cluster or {}).get("enable"), default=False),
                # A node's firewall is on unless switched off explicitly.
                "node_enabled": (
                    _flag(node.get("enable"), default=True) if node is not None else None
                ),
                "policy_in": str((cluster or {}).get("policy_in") or "") or None,
                "policy_out": str((cluster or {}).get("policy_out") or "") or None,
            }
    return {
        "units": {name: units.get(name) for name in UNITS if units.get(name)},
        "nftables_installed": "NFT" in blocks,
        "nftables": nft,
        "ufw": ufw,
        "pve": pve,
    }


def _parse_time(value: str | None) -> str | None:
    if not value:
        return None
    try:
        # Fail2Ban prints the machine's local time without a zone; kept as
        # written (naive ISO), the UI shows it as the machine reported it.
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").isoformat()
    except ValueError:
        return None


def parse_fail2ban_section(section: str) -> dict[str, Any] | None:
    """`{"status": "ok"|"stopped"|"no_access", "jails": [...]}`; None when
    Fail2Ban is not installed."""
    lines = section.splitlines()
    if not any(line.startswith("@@UNIT") for line in lines):
        return None
    unit = next((line.split()[1] for line in lines if line.startswith("@@UNIT") and
                 len(line.split()) > 1), "unknown")
    if "@@OK" not in lines:
        return {"status": "stopped" if unit != "active" else "no_access", "jails": []}
    jails: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_bans = False
    for line in lines:
        if line.startswith("@@JAIL "):
            name = line[len("@@JAIL ") :].strip()
            current = None
            in_bans = False
            if _JAIL_NAME_RE.match(name) and len(jails) < MAX_JAILS:
                current = {
                    "name": name,
                    "currently_failed": None,
                    "total_failed": None,
                    "currently_banned": None,
                    "total_banned": None,
                    "bans": [],
                }
                jails.append(current)
            continue
        if current is None:
            continue
        if line.strip() == "@@BANS":
            in_bans = True
            continue
        if not in_bans:
            match = _COUNT_RE.search(line)
            if match is not None:
                current[match.group(1).lower().replace(" ", "_")] = int(match.group(2))
            continue
        ban = _BAN_RE.match(line.strip())
        if ban is None or not _IP_RE.match(ban.group(1)):
            continue
        if len(current["bans"]) < MAX_BANS_PER_JAIL:
            current["bans"].append(
                {
                    "ip": ban.group(1),
                    "since": _parse_time(ban.group(2)),
                    "seconds": int(ban.group(3)),
                    "until": _parse_time(ban.group(4)),
                }
            )
    for jail in jails:
        jail["bans"].sort(key=lambda b: b["since"] or "", reverse=True)
    return {"status": "ok", "jails": jails}


# --- Reading what is stored -------------------------------------------------


def active_backends(firewall: dict[str, Any] | None) -> list[str]:
    """The packet filters actually in force: a running ufw / firewalld,
    an enabled Proxmox VE firewall, and nftables when an input hook drops
    by default or has rules of its own."""
    if not firewall:
        return []
    units = firewall.get("units") or {}
    found: list[str] = []
    ufw = firewall.get("ufw") or {}
    if ufw.get("active") or (ufw.get("active") is None and units.get("ufw") == "active"):
        found.append("ufw")
    if units.get("firewalld") == "active":
        found.append("firewalld")
    pve = firewall.get("pve") or {}
    if pve.get("cluster_enabled") and pve.get("node_enabled") is not False:
        found.append("pve-firewall")
    # ufw and firewalld program nftables themselves — named on their own,
    # nftables only when nothing above manages it.
    if not found:
        nft = firewall.get("nftables")
        if nft is not None:
            chains = nft.get("input_chains") or []
            if any(c.get("policy") == "drop" or c.get("rules") for c in chains):
                found.append("nftables")
        elif units.get("nftables") == "active":
            found.append("nftables")
    return found


def protection(firewall: dict[str, Any] | None) -> str:
    """"on" (some filter in force), "off" (readable, nothing in force) or
    "unknown" (not collected yet, or the ruleset could not be read)."""
    if firewall is None:
        return "unknown"
    if active_backends(firewall):
        return "on"
    readable = firewall.get("nftables") is not None or (
        (firewall.get("ufw") or {}).get("readable")
    )
    if readable or not firewall.get("nftables_installed"):
        return "off"
    return "unknown"


def input_policy(firewall: dict[str, Any] | None) -> str | None:
    """The strictest input policy seen in nftables ("drop" beats
    "accept"), else ufw's or the Proxmox VE firewall's incoming default."""
    nft = (firewall or {}).get("nftables") or {}
    policies = {str(c.get("policy")) for c in nft.get("input_chains") or []}
    if "drop" in policies:
        return "drop"
    if policies:
        return "accept"
    ufw = (firewall or {}).get("ufw") or {}
    match = re.search(r"(\w+) \(incoming\)", str(ufw.get("defaults") or ""))
    if ufw.get("active") and match is not None:
        return match.group(1).lower()
    pve = (firewall or {}).get("pve") or {}
    if pve.get("cluster_enabled") and pve.get("policy_in"):
        return str(pve["policy_in"]).lower()
    return None


def fail2ban_totals(fail2ban: dict[str, Any] | None) -> dict[str, Any]:
    """`{"jails", "currently_banned", "total_banned", "last_ban"}`."""
    jails = (fail2ban or {}).get("jails") or []
    last = max(
        (b.get("since") or "" for j in jails for b in j.get("bans") or []), default=""
    )
    return {
        "jails": len(jails),
        "currently_banned": sum(int(j.get("currently_banned") or 0) for j in jails),
        "total_banned": sum(int(j.get("total_banned") or 0) for j in jails),
        "last_ban": last or None,
    }


def recent_bans(fail2ban: dict[str, Any] | None, limit: int = 20) -> list[dict[str, Any]]:
    """The newest current bans across all jails, each with its jail."""
    rows = [
        {**ban, "jail": jail.get("name")}
        for jail in (fail2ban or {}).get("jails") or []
        for ban in jail.get("bans") or []
    ]
    rows.sort(key=lambda b: b.get("since") or "", reverse=True)
    return rows[:limit]



def overview(firewall: dict[str, Any] | None, fail2ban: dict[str, Any] | None) -> dict[str, Any]:
    """What the Security pages and the API show for one machine."""
    return {
        "protection": protection(firewall),
        "backends": active_backends(firewall),
        "input_policy": input_policy(firewall),
        "rules": ((firewall or {}).get("nftables") or {}).get("rules"),
        "fail2ban_status": (fail2ban or {}).get("status"),
        "fail2ban": fail2ban_totals(fail2ban),
    }
