"""Proxmox VE and ZFS: guests, pools, storage and backups.

Two command fragments, each appended to an existing round trip rather than
opening one of its own (see `app.ssh.pool` for why fewer logins matter):

- `LIVE_COMMAND`, with every monitoring sample (`app.ssh.monitoring`):
  ZFS pool capacity/health (`zpool list`/`zpool status`, any host with
  ZFS — not only Proxmox) and, on Proxmox VE, every VM/container with its
  state (`pvesh get /cluster/resources --type vm`). Things that change
  minute to minute.
- `INVENTORY_COMMAND`, with every facts refresh (`app.ssh.facts`): the
  Proxmox VE version (`pveversion`), storages (including Proxmox Backup
  Server ones) with their usage, backup jobs, the last backup tasks and
  their result, and guests no backup job covers.

`pvesh` talks to the local API as root — run through `sudo -n` like every
other privileged read here (a no-op for a root account, see
`app.ssh.shell`); an unprivileged account without a grant simply gets
empty sections. Each part is guarded with `command -v`, so a machine
without ZFS or Proxmox costs nothing but an `echo`.

Every parser here is pure (no I/O) and never raises on malformed input —
an optional reading must never fail a whole sample.
"""

from __future__ import annotations

import json
import re
from typing import Any

LIVE_MARKERS = ("ZFS_POOLS", "ZFS_STATUS", "PVE_GUESTS")
INVENTORY_MARKERS = (
    "PVE_VERSION",
    "PVE_STORAGE",
    "PVE_BACKUP_TASKS",
    "PVE_BACKUP_JOBS",
    "PVE_NOT_BACKED_UP",
)

_PVESH = "sudo -n pvesh get"
_JSON = "--output-format json 2>/dev/null"

LIVE_COMMAND = (
    "echo ===ZFS_POOLS===; "
    "if command -v zpool >/dev/null 2>&1; then "
    "zpool list -H -p -o name,size,alloc,free,frag,cap,health 2>/dev/null; fi; "
    "echo ===ZFS_STATUS===; "
    "if command -v zpool >/dev/null 2>&1; then zpool status 2>/dev/null; fi; "
    "echo ===PVE_GUESTS===; "
    f"if command -v pvesh >/dev/null 2>&1; then {_PVESH} /cluster/resources --type vm {_JSON}; fi"
)

INVENTORY_COMMAND = (
    "echo ===PVE_VERSION===; "
    "if command -v pveversion >/dev/null 2>&1; then pveversion 2>/dev/null; fi; "
    "if command -v pvesh >/dev/null 2>&1; then "
    f"echo ===PVE_STORAGE===; {_PVESH} /nodes/localhost/storage {_JSON}; "
    "echo ===PVE_BACKUP_TASKS===; "
    f"{_PVESH} /nodes/localhost/tasks --typefilter vzdump --limit 10 {_JSON}; "
    f"echo ===PVE_BACKUP_JOBS===; {_PVESH} /cluster/backup {_JSON}; "
    f"echo ===PVE_NOT_BACKED_UP===; {_PVESH} /cluster/backup-info/not-backed-up {_JSON}; "
    "fi"
)

_PVE_VERSION_RE = re.compile(r"pve-manager/(\d+(?:\.\d+)+)")


def parse_pve_version(section: str) -> str | None:
    """`pve-manager/8.2.4/faa8… (running kernel: …)` -> "8.2.4"."""
    match = _PVE_VERSION_RE.search(section)
    return match.group(1) if match else None


def _json_list(section: str) -> list[dict[str, Any]] | None:
    """A `pvesh … --output-format json` array, or None when the section is
    empty or not JSON (no `pvesh`, no permission)."""
    text = section.strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    return [item for item in data if isinstance(item, dict)]


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _float(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def parse_guests(section: str) -> list[dict[str, Any]] | None:
    """VMs and containers from `/cluster/resources --type vm`, sorted by
    VMID: `{"vmid", "name", "type" ("qemu"/"lxc"), "node", "status",
    "cpu_percent", "mem_bytes", "maxmem_bytes", "uptime_seconds",
    "template", "tags"}`. None = not a Proxmox VE host (or no access)."""
    rows = _json_list(section)
    if rows is None:
        return None
    guests: list[dict[str, Any]] = []
    for row in rows:
        vmid = _int(row.get("vmid"))
        guest_type = str(row.get("type") or "")
        if vmid is None or guest_type not in ("qemu", "lxc"):
            continue
        cpu = _float(row.get("cpu"))
        tags = str(row.get("tags") or "")
        guests.append(
            {
                "vmid": vmid,
                "name": str(row.get("name") or ""),
                "type": guest_type,
                "node": str(row.get("node") or ""),
                "status": str(row.get("status") or "unknown"),
                "cpu_percent": round(cpu * 100, 1) if cpu is not None else None,
                "mem_bytes": _int(row.get("mem")),
                "maxmem_bytes": _int(row.get("maxmem")),
                "uptime_seconds": _int(row.get("uptime")),
                "template": bool(_int(row.get("template")) or 0),
                "tags": [t for t in re.split(r"[;, ]+", tags) if t],
            }
        )
    guests.sort(key=lambda g: g["vmid"])
    return guests


def _zfs_number(value: str) -> int | None:
    return int(value) if value.isdigit() else None


def parse_zfs_pools(list_section: str, status_section: str) -> list[dict[str, Any]] | None:
    """`zpool list -H -p` rows merged with `zpool status` details:
    `{"name", "size_bytes", "alloc_bytes", "free_bytes", "frag_percent",
    "cap_percent", "health", "status", "scan", "errors"}`. `status` is
    zpool's own explanation of a problem (empty when healthy), `scan` the
    last scrub/resilver line, `errors` its data-error summary. None = no
    ZFS on this machine."""
    if not list_section.strip():
        return None
    details = _parse_zpool_status(status_section)
    pools: list[dict[str, Any]] = []
    for line in list_section.splitlines():
        fields = line.split("\t") if "\t" in line else line.split()
        if len(fields) < 7:
            continue
        name, size, alloc, free, frag, cap, health = (f.strip() for f in fields[:7])
        extra = details.get(name, {})
        pools.append(
            {
                "name": name,
                "size_bytes": _zfs_number(size),
                "alloc_bytes": _zfs_number(alloc),
                "free_bytes": _zfs_number(free),
                "frag_percent": _zfs_number(frag.rstrip("%")),
                "cap_percent": _zfs_number(cap.rstrip("%")),
                "health": health,
                "status": extra.get("status", ""),
                "scan": extra.get("scan", ""),
                "errors": extra.get("errors", ""),
            }
        )
    return pools


# `zpool status` header lines: a right-aligned key, a colon, the value.
_STATUS_KEY_RE = re.compile(r"^ {0,6}([a-z]+):(?: (.*))?$")
_KEPT_KEYS = ("status", "scan", "errors")


def _parse_zpool_status(raw: str) -> dict[str, dict[str, str]]:
    """{pool: {"status", "scan", "errors"}} from `zpool status`'s
    `key: value` header lines. A value continues on following lines that
    start with a tab — the device tree under `config:` does too, which is
    why only `status`/`scan` ever take continuations."""
    pools: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    key: str | None = None
    for line in raw.splitlines():
        match = None if line.startswith("\t") else _STATUS_KEY_RE.match(line)
        if match:
            key = match.group(1)
            value = (match.group(2) or "").strip()
            if key == "pool":
                current = pools.setdefault(value, dict.fromkeys(_KEPT_KEYS, ""))
            elif current is not None and key in _KEPT_KEYS:
                current[key] = value
            continue
        if current is not None and key in ("status", "scan") and line.startswith("\t"):
            current[key] = f"{current[key]} {line.strip()}".strip()
    return pools


def parse_storage(section: str) -> list[dict[str, Any]] | None:
    """Storages from `/nodes/localhost/storage`: `{"name", "type",
    "active", "enabled", "shared", "content", "total_bytes", "used_bytes",
    "avail_bytes", "used_percent"}` — a Proxmox Backup Server storage is
    `type == "pbs"`."""
    rows = _json_list(section)
    if rows is None:
        return None
    storages: list[dict[str, Any]] = []
    for row in rows:
        name = str(row.get("storage") or "")
        if not name:
            continue
        total = _int(row.get("total"))
        used = _int(row.get("used"))
        fraction = _float(row.get("used_fraction"))
        if fraction is None and total and used is not None:
            fraction = used / total
        storages.append(
            {
                "name": name,
                "type": str(row.get("type") or ""),
                "active": bool(_int(row.get("active")) or 0),
                "enabled": bool(_int(row.get("enabled", 1)) or 0),
                "shared": bool(_int(row.get("shared")) or 0),
                "content": str(row.get("content") or ""),
                "total_bytes": total,
                "used_bytes": used,
                "avail_bytes": _int(row.get("avail")),
                "used_percent": round(fraction * 100, 1) if fraction is not None else None,
            }
        )
    storages.sort(key=lambda s: s["name"])
    return storages


def _task_ok(status: str) -> bool | None:
    """vzdump task status: "OK" (and "WARNINGS: n", which still produced
    every backup) is success; anything else is a failure; still running
    ("") is unknown."""
    if not status:
        return None
    return status == "OK" or status.startswith("WARNINGS")


def parse_backups(
    tasks_section: str, jobs_section: str, not_backed_up_section: str
) -> dict[str, Any] | None:
    """`{"tasks": [...], "jobs": [...], "not_backed_up": [...]}`, or None
    when none of the three could be read (not Proxmox VE).

    - tasks: the last vzdump runs, newest first — `{"id", "started_at",
      "ended_at", "status", "ok"}` (epoch seconds; `id` is the guest for a
      single-guest run, empty for a whole job);
    - jobs: configured backup jobs — `{"id", "schedule", "storage",
      "enabled", "selection", "next_run", "comment"}`;
    - not_backed_up: guests no job covers — `{"vmid", "name", "type"}`."""
    tasks_rows = _json_list(tasks_section)
    jobs_rows = _json_list(jobs_section)
    missing_rows = _json_list(not_backed_up_section)
    if tasks_rows is None and jobs_rows is None and missing_rows is None:
        return None
    tasks = []
    for row in tasks_rows or []:
        status = str(row.get("status") or "")
        tasks.append(
            {
                "id": str(row.get("id") or ""),
                "started_at": _int(row.get("starttime")),
                "ended_at": _int(row.get("endtime")),
                "status": status,
                "ok": _task_ok(status),
            }
        )
    tasks.sort(key=lambda t: t["started_at"] or 0, reverse=True)
    jobs = []
    for row in jobs_rows or []:
        selection = "all" if row.get("all") else str(row.get("vmid") or row.get("pool") or "")
        jobs.append(
            {
                "id": str(row.get("id") or ""),
                "schedule": str(row.get("schedule") or row.get("starttime") or ""),
                "storage": str(row.get("storage") or ""),
                "enabled": bool(_int(row.get("enabled", 1)) or 0),
                "selection": selection,
                "next_run": _int(row.get("next-run")),
                "comment": str(row.get("comment") or ""),
            }
        )
    not_backed_up = [
        {
            "vmid": _int(row.get("vmid")),
            "name": str(row.get("name") or ""),
            "type": str(row.get("type") or ""),
        }
        for row in missing_rows or []
        if _int(row.get("vmid")) is not None
    ]
    return {"tasks": tasks, "jobs": jobs, "not_backed_up": not_backed_up}


def guest_counts(guests: list[dict[str, Any]] | None) -> tuple[int, int]:
    """(running, total) guests, templates not counted."""
    real = [g for g in guests or [] if not g.get("template")]
    return sum(1 for g in real if g.get("status") == "running"), len(real)


def unhealthy_pools(pools: list[dict[str, Any]] | None) -> list[str]:
    """Names of pools whose health isn't ONLINE."""
    return [p["name"] for p in pools or [] if str(p.get("health")) != "ONLINE"]


def last_backup(backups: dict[str, Any] | None) -> dict[str, Any] | None:
    """The newest finished backup task, or None."""
    for task in (backups or {}).get("tasks", []):
        if task.get("ok") is not None:
            return dict(task)
    return None
