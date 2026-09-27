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

LIVE_MARKERS = ("ZFS_POOLS", "ZFS_STATUS", "PVE_GUESTS", "PVE_CLUSTER")
INVENTORY_MARKERS = (
    "PVE_VERSION",
    "PVE_STORAGE",
    "PVE_BACKUP_TASKS",
    "PVE_BACKUP_JOBS",
    "PVE_NOT_BACKED_UP",
    "PVE_FAILED_TASKS",
    "PBS_VERSION",
    "PBS_USAGE",
    "PBS_GC",
    "PBS_VERIFY",
    "PBS_SYNC",
    "PBS_PRUNE",
    "PBS_TASKS",
    "PBS_GROUPS",
    "PMG_VERSION",
    "PMG_STATS",
    "PMG_QUEUE",
    "PMG_CLAMAV",
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
    f"if command -v pvesh >/dev/null 2>&1; then {_PVESH} /cluster/resources --type vm {_JSON}; fi; "
    "echo ===PVE_CLUSTER===; "
    f"if command -v pvesh >/dev/null 2>&1; then {_PVESH} /cluster/status {_JSON}; fi"
)

# Proxmox Backup Server: its local API through `proxmox-backup-debug api`
# (root), the same data its web UI shows. Datastore names are PBS
# identifiers ([A-Za-z0-9_.-]) — anything else is skipped rather than
# passed to the shell.
_PBSAPI = "sudo -n proxmox-backup-debug api get"
_PBS_COMMAND = (
    "if command -v proxmox-backup-manager >/dev/null 2>&1; then "
    "echo ===PBS_VERSION===; "
    "dpkg-query -W -f='${Version}\\n' proxmox-backup-server 2>/dev/null; "
    f"echo ===PBS_USAGE===; {_PBSAPI} /status/datastore-usage {_JSON}; "
    f"echo ===PBS_GC===; {_PBSAPI} /admin/gc {_JSON}; "
    f"echo ===PBS_VERIFY===; {_PBSAPI} /admin/verify {_JSON}; "
    f"echo ===PBS_SYNC===; {_PBSAPI} /admin/sync {_JSON}; "
    f"echo ===PBS_PRUNE===; {_PBSAPI} /admin/prune {_JSON}; "
    f"echo ===PBS_TASKS===; {_PBSAPI} /nodes/localhost/tasks --limit 25 {_JSON}; "
    "echo ===PBS_GROUPS===; "
    "for s in $(sudo -n proxmox-backup-manager datastore list --output-format json-pretty "
    "2>/dev/null | sed -n 's/.*\"name\": *\"\\([^\"]*\\)\".*/\\1/p'); do "
    'case "$s" in *[!A-Za-z0-9_.-]*) continue;; esac; '
    'echo "@@STORE $s"; '
    f'{_PBSAPI} "/admin/datastore/$s/groups" {_JSON}; echo; '
    "done; "
    "fi"
)

# Proxmox Mail Gateway: `pmgsh` (its API shell, root; prints JSON) and the
# Postfix queue (`postqueue -j`, one JSON object per queued message).
_PMGSH = "sudo -n pmgsh get"
_PMG_COMMAND = (
    "if command -v pmgversion >/dev/null 2>&1; then "
    "echo ===PMG_VERSION===; pmgversion 2>/dev/null; "
    "echo ===PMG_STATS===; "
    'now="$(date +%s)"; '
    f'{_PMGSH} /statistics/mail --starttime "$((now - 86400))" --endtime "$now" 2>/dev/null; '
    # `@@OK` only when postqueue itself ran — an empty queue then reads as
    # zero messages, not as "couldn't tell".
    "echo ===PMG_QUEUE===; "
    'if q="$(sudo -n postqueue -j 2>/dev/null)"; then echo @@OK; echo "$q"; fi; '
    f"echo ===PMG_CLAMAV===; {_PMGSH} /nodes/localhost/clamav/database 2>/dev/null; "
    "fi"
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
    "echo ===PVE_FAILED_TASKS===; "
    f"{_PVESH} /nodes/localhost/tasks --errors 1 --limit 15 {_JSON}; "
    "fi; "
    f"{_PBS_COMMAND}; "
    f"{_PMG_COMMAND}"
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


# --- Proxmox VE cluster and failed tasks -----------------------------------


def parse_cluster(section: str) -> dict[str, Any] | None:
    """`/cluster/status`: `{"name", "quorate", "nodes": [{"name", "online",
    "local", "ip"}]}` — `name`/`quorate` None on a standalone node (no
    cluster entry). None when not Proxmox VE."""
    rows = _json_list(section)
    if rows is None:
        return None
    cluster: dict[str, Any] = {"name": None, "quorate": None, "nodes": []}
    for row in rows:
        if row.get("type") == "cluster":
            cluster["name"] = str(row.get("name") or "") or None
            quorate = _int(row.get("quorate"))
            cluster["quorate"] = None if quorate is None else bool(quorate)
        elif row.get("type") == "node":
            cluster["nodes"].append(
                {
                    "name": str(row.get("name") or ""),
                    "online": bool(_int(row.get("online")) or 0),
                    "local": bool(_int(row.get("local")) or 0),
                    "ip": str(row.get("ip") or ""),
                }
            )
    cluster["nodes"].sort(key=lambda n: n["name"])
    return cluster


def _task_rows(section: str, *, type_key: str, id_key: str) -> list[dict[str, Any]] | None:
    rows = _json_list(section)
    if rows is None:
        return None
    tasks = []
    for row in rows:
        status = str(row.get("status") or "")
        tasks.append(
            {
                "type": str(row.get(type_key) or ""),
                "id": str(row.get(id_key) or ""),
                "started_at": _int(row.get("starttime")),
                "ended_at": _int(row.get("endtime")),
                "status": status,
                "ok": _task_ok(status),
            }
        )
    tasks.sort(key=lambda t: t["started_at"] or 0, reverse=True)
    return tasks


def parse_failed_tasks(section: str) -> list[dict[str, Any]] | None:
    """Proxmox VE's recent failed tasks of any kind (`--errors 1`)."""
    return _task_rows(section, type_key="type", id_key="id")


# --- Proxmox Backup Server ---------------------------------------------------------


def _job_rows(section: str) -> list[dict[str, Any]] | None:
    """GC / verify / sync / prune job lists: `{"id", "store", "schedule",
    "last_state", "ok", "last_run", "next_run", "remote"}`."""
    rows = _json_list(section)
    if rows is None:
        return None
    jobs = []
    for row in rows:
        state = str(row.get("last-run-state") or "")
        jobs.append(
            {
                "id": str(row.get("id") or row.get("store") or ""),
                "store": str(row.get("store") or ""),
                "schedule": str(row.get("schedule") or row.get("gc-schedule") or ""),
                "last_state": state,
                "ok": None if not state else state.upper() == "OK",
                "last_run": _int(row.get("last-run-endtime")),
                "next_run": _int(row.get("next-run")),
                "remote": str(row.get("remote") or ""),
                "removed_bytes": _int(row.get("removed-bytes")),
                "pending_bytes": _int(row.get("pending-bytes")),
            }
        )
    jobs.sort(key=lambda j: (j["store"], j["id"]))
    return jobs


def _parse_groups(section: str) -> dict[str, list[dict[str, Any]]]:
    """`@@STORE name` then that store's `/groups` JSON, per datastore."""
    stores: dict[str, list[dict[str, Any]]] = {}
    current: str | None = None
    buffer: list[str] = []

    def flush() -> None:
        if current is None:
            return
        rows = _json_list("\n".join(buffer)) or []
        stores[current] = sorted(
            (
                {
                    "type": str(r.get("backup-type") or ""),
                    "id": str(r.get("backup-id") or ""),
                    "last_backup": _int(r.get("last-backup")),
                    "count": _int(r.get("backup-count")),
                    "comment": str(r.get("comment") or ""),
                }
                for r in rows
            ),
            key=lambda g: (g["type"], g["id"]),
        )

    for line in section.splitlines():
        if line.startswith("@@STORE "):
            flush()
            current = line[len("@@STORE ") :].strip()
            buffer = []
        else:
            buffer.append(line)
    flush()
    return stores


def parse_pbs(sections: dict[str, str]) -> tuple[str | None, dict[str, Any] | None]:
    """(version, data) of a Proxmox Backup Server from the `PBS_*`
    sections; (None, None) when it isn't one. data: `datastores` (usage,
    estimated full date), `gc`/`verify`/`sync`/`prune` jobs, recent
    `tasks` and backup `groups` per datastore."""
    version_text = sections.get("PBS_VERSION", "").strip()
    if not version_text:
        return None, None
    version = version_text.split("-", 1)[0] or version_text
    datastores = []
    for row in _json_list(sections.get("PBS_USAGE", "")) or []:
        total = _int(row.get("total"))
        used = _int(row.get("used"))
        datastores.append(
            {
                "name": str(row.get("store") or ""),
                "total_bytes": total,
                "used_bytes": used,
                "avail_bytes": _int(row.get("avail")),
                "used_percent": round(used / total * 100, 1)
                if total and used is not None
                else None,
                "full_at": _int(row.get("estimated-full-date")),
                "error": str(row.get("error") or ""),
            }
        )
    datastores.sort(key=lambda d: str(d["name"]))
    data = {
        "datastores": datastores,
        "gc": _job_rows(sections.get("PBS_GC", "")) or [],
        "verify": _job_rows(sections.get("PBS_VERIFY", "")) or [],
        "sync": _job_rows(sections.get("PBS_SYNC", "")) or [],
        "prune": _job_rows(sections.get("PBS_PRUNE", "")) or [],
        "tasks": _task_rows(
            sections.get("PBS_TASKS", ""), type_key="worker_type", id_key="worker_id"
        )
        or [],
        "groups": _parse_groups(sections.get("PBS_GROUPS", "")),
    }
    return version, data


def pbs_failures(data: dict[str, Any] | None) -> list[str]:
    """One line per PBS job whose last run failed and per failed task."""
    if not data:
        return []
    lines = [
        f"{kind} {job['id']}: {job['last_state']}"
        for kind in ("gc", "verify", "sync", "prune")
        for job in data.get(kind) or []
        if job.get("ok") is False
    ]
    lines += [
        f"{task['type']} {task['id']}: {task['status']}"
        for task in data.get("tasks") or []
        if task.get("ok") is False
    ]
    return lines


# Backup groups whose newest snapshot is older than this are flagged.
STALE_BACKUP_SECONDS = 2 * 86400


# --- Proxmox Mail Gateway -----------------------------------------------------------

_PMG_VERSION_RE = re.compile(r"pmg/(\d+(?:\.\d+)+)")

_STAT_KEYS = (
    "count",
    "count_in",
    "count_out",
    "spamcount_in",
    "spamcount_out",
    "viruscount_in",
    "viruscount_out",
    "bounces_in",
    "bounces_out",
    "rbl_rejects",
    "pregreet_rejects",
    "junk_in",
    "bytes_in",
    "bytes_out",
)


def _json_value(section: str) -> Any:
    text = section.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def parse_pmg(sections: dict[str, str]) -> tuple[str | None, dict[str, Any] | None]:
    """(version, data) of a Proxmox Mail Gateway; (None, None) otherwise.
    data: `stats` (the last 24 h: mail in/out, spam, viruses, bounces, RBL
    and pregreet rejects), `queue` (Postfix message counts per queue) and
    `clamav` (signature databases with version and build time)."""
    match = _PMG_VERSION_RE.search(sections.get("PMG_VERSION", ""))
    if not match:
        return None, None
    stats_raw = _json_value(sections.get("PMG_STATS", ""))
    if isinstance(stats_raw, list):
        stats_raw = stats_raw[0] if stats_raw and isinstance(stats_raw[0], dict) else None
    stats = (
        {key: _int(stats_raw.get(key)) for key in _STAT_KEYS}
        if isinstance(stats_raw, dict)
        else None
    )
    queue: dict[str, int] | None = None
    queue_lines = sections.get("PMG_QUEUE", "").splitlines()
    if queue_lines and queue_lines[0].strip() == "@@OK":
        queue = {"active": 0, "deferred": 0, "hold": 0, "incoming": 0}
        for line in queue_lines[1:]:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and entry.get("queue_name"):
                name = str(entry["queue_name"])
                queue[name] = queue.get(name, 0) + 1
    clamav_raw = _json_value(sections.get("PMG_CLAMAV", ""))
    clamav = [
        {
            "type": str(row.get("type") or ""),
            "version": str(row.get("version") or ""),
            "signatures": _int(row.get("nsigs")),
            "build_time": str(row.get("build_time") or ""),
        }
        for row in (clamav_raw if isinstance(clamav_raw, list) else [])
        if isinstance(row, dict)
    ]
    return match.group(1), {"stats": stats, "queue": queue, "clamav": clamav}


# The mail queue counts as backed up at this many deferred/held messages.
MAIL_QUEUE_WARN = 50


def mail_queue_backlog(data: dict[str, Any] | None) -> int:
    queue = (data or {}).get("queue") or {}
    return int(queue.get("deferred", 0)) + int(queue.get("hold", 0))


# --- Starting and stopping guests ------------------------------------------------

# `shutdown` asks the guest OS to power off (ACPI / the container's init);
# `stop` pulls the plug.
GUEST_ACTIONS = ("start", "shutdown", "reboot", "stop")
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")


def find_guest(guests: list[dict[str, Any]] | None, vmid: int) -> dict[str, Any] | None:
    return next((g for g in guests or [] if g.get("vmid") == vmid), None)


def build_guest_action_command(guest: dict[str, Any], action: str) -> str:
    """`pvesh create /nodes/<node>/<qemu|lxc>/<vmid>/status/<action>` for a
    guest from the latest sample. Every part is checked against a strict
    pattern before it reaches the shell."""
    if action not in GUEST_ACTIONS:
        raise ValueError(f'"{action}" is not a guest action.')
    guest_type = str(guest.get("type") or "")
    node = str(guest.get("node") or "")
    vmid = guest.get("vmid")
    if guest_type not in ("qemu", "lxc") or not isinstance(vmid, int) or not _NODE_RE.match(node):
        raise ValueError("Unknown guest.")
    return f"sudo -n pvesh create /nodes/{node}/{guest_type}/{vmid}/status/{action} 2>&1"
