"""Gather one CPU/RAM/network/disk-I/O/filesystem-usage sample from a
managed machine — the Monitoring tab's trend graphs. Read-only, no root
needed for any of it (same convention as `app.ssh.facts`).

Deliberately its own, much lighter, round trip than `app.ssh.facts` — this
runs on a much shorter cadence (`MONITORING_INTERVAL_SECONDS`, 2 minutes by
default, vs. facts' default 10 minutes), so it only gathers what a
frequent sample actually needs: CPU/load/RAM/network/disk-I/O/filesystem-
usage right now, plus a cheap *count* of failed systemd services (the full
unit list is `app.ssh.services`, on the facts cadence instead — see that
module's own docstring for why).

Filesystem usage (`df`, same command `app.ssh.facts` already runs) *is*
gathered here too, on this shorter cadence, precisely so the Monitoring
tab can show a *history* of how full a mount is over time — the Overview
tab's Facts panel only ever showed the single most recent reading, no
trend. It's a small, cheap addition to a round trip that already exists,
not a separate connection.
"""

from __future__ import annotations

import re
from typing import Any, TypedDict

from app.db.models.machine import Machine
from app.ssh.client import open_connection

_SECTION_MARKERS = ("CPU", "LOAD", "RAM_KB", "NET", "DISKIO", "FILESYSTEMS", "FAILED_SERVICES")

# CPU percent needs two samples of /proc/stat a moment apart — computed
# entirely in the one round trip (a 1-second `sleep`) rather than as two
# separate SSH round trips, so this whole command still only takes about a
# second longer than a plain connect. POSIX `read` (works in `sh`/`dash`,
# Debian's default `/bin/sh`) splits the line into the named fields;
# `awk` does the float-safe percentage math `sh` arithmetic can't.
#
# NET: `/proc/net/dev`'s own column layout — `face: rx_bytes rx_packets
# rx_errs rx_drop rx_fifo rx_frame rx_compressed rx_multicast tx_bytes
# ...` (checked against the kernel's own documented format, not assumed).
# `lo` is skipped — loopback traffic isn't "network" for monitoring
# purposes. Cumulative counters since boot, same shape a Prometheus-style
# collector would report — the *rate* (bytes/sec) is computed later from
# consecutive samples (`app.services.monitoring_history`), not here.
#
# DISKIO: `/proc/diskstats`'s `sectors_read`/`sectors_written` columns
# (fields 6 and 10; 512-byte sectors, the kernel's own fixed unit
# regardless of the device's real block size) filtered down to whole
# disks only (via `lsblk -d`, the same tool `app.ssh.facts` already uses
# for this) — a partition's numbers would otherwise double-count against
# its parent disk's.
MONITORING_COMMAND = (
    "echo ===CPU===; "
    "{ read -r _ u1 n1 s1 i1 w1 irq1 sirq1 _ < /proc/stat; "
    "sleep 1; "
    "read -r _ u2 n2 s2 i2 w2 irq2 sirq2 _ < /proc/stat; "
    "awk -v u1=\"$u1\" -v n1=\"$n1\" -v s1=\"$s1\" -v i1=\"$i1\" -v w1=\"$w1\" "
    "-v irq1=\"$irq1\" -v sirq1=\"$sirq1\" "
    "-v u2=\"$u2\" -v n2=\"$n2\" -v s2=\"$s2\" -v i2=\"$i2\" -v w2=\"$w2\" "
    "-v irq2=\"$irq2\" -v sirq2=\"$sirq2\" 'BEGIN { "
    "t1 = u1+n1+s1+i1+w1+irq1+sirq1; t2 = u2+n2+s2+i2+w2+irq2+sirq2; "
    "idle1 = i1+w1; idle2 = i2+w2; "
    "td = t2-t1; idled = idle2-idle1; "
    "if (td > 0) printf \"%.1f\\n\", (td-idled)*100/td; "
    "}'; "
    "} 2>/dev/null; "
    "echo ===LOAD===; "
    "awk '{print $1, $2, $3}' /proc/loadavg 2>/dev/null; "
    "echo ===RAM_KB===; "
    "awk '/MemTotal/ {total=$2} /MemAvailable/ {avail=$2} "
    "END { if (total > 0) printf \"%d %d\\n\", total, total-avail }' "
    "/proc/meminfo 2>/dev/null; "
    "echo ===NET===; "
    "awk 'NR>2 {gsub(\":\", \"\", $1); if ($1 != \"lo\") print $1, $2, $10}' "
    "/proc/net/dev 2>/dev/null; "
    "echo ===DISKIO===; "
    "disks=\"$(lsblk -d -n -o NAME 2>/dev/null)\"; "
    "awk -v disks=\"$disks\" 'BEGIN { n = split(disks, arr, \" \"); "
    "for (i = 1; i <= n; i++) want[arr[i]] = 1 } "
    "$3 in want { print $3, $6*512, $10*512 }' /proc/diskstats 2>/dev/null; "
    "echo ===FILESYSTEMS===; "
    "df -B1 --output=target,size,used,avail,pcent "
    "-x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2; "
    "echo ===FAILED_SERVICES===; "
    "if command -v systemctl >/dev/null 2>&1; then "
    "systemctl --failed --plain --no-legend --no-pager 2>/dev/null | wc -l; "
    "fi"
)


class MonitoringSample(TypedDict):
    cpu_percent: float | None
    # 1/5/15-minute load averages (`/proc/loadavg`) — a count of
    # runnable+uninterruptible processes, not a percentage; can exceed
    # `cpu_cores` under real contention, unlike cpu_percent.
    load1: float | None
    load5: float | None
    load15: float | None
    ram_used_bytes: int | None
    ram_total_bytes: int | None
    # Each {"iface": ..., "rx_bytes": ..., "tx_bytes": ...} — cumulative
    # counters since boot, one entry per non-loopback interface found.
    network_io: list[dict[str, Any]]
    # Each {"device": ..., "read_bytes": ..., "write_bytes": ...} —
    # cumulative counters since boot, one entry per whole disk found.
    disk_io: list[dict[str, Any]]
    # Each {"mount": ..., "size_bytes": ..., "used_bytes": ..., "avail_bytes":
    # ..., "use_percent": ...} — same shape/exclusions (no tmpfs/devtmpfs/
    # squashfs/overlay) as `app.ssh.facts.MachineFacts["filesystems"]`.
    filesystems: list[dict[str, Any]]
    # None = couldn't tell (no systemd), not "zero failed".
    failed_services_count: int | None


def _split_sections(raw: str) -> dict[str, str]:
    pattern = "|".join(f"==={name}===" for name in _SECTION_MARKERS)
    parts = re.split(f"(?:{pattern})", raw)
    body = parts[1:]
    return dict(zip(_SECTION_MARKERS, (chunk.strip() for chunk in body), strict=False))


_FLOAT_RE = re.compile(r"^-?\d+(\.\d+)?$")


def _parse_float(value: str) -> float | None:
    return float(value) if _FLOAT_RE.match(value) else None


def parse_monitoring_output(raw: str) -> MonitoringSample:
    """Parse `MONITORING_COMMAND`'s output. Pure function, no I/O — kept
    separate from `gather_monitoring_sample` so it can be unit-tested
    against canned output, same convention as `app.ssh.facts.
    parse_facts_output`."""
    sections = _split_sections(raw)

    cpu_percent = _parse_float(sections.get("CPU", ""))

    load1 = load5 = load15 = None
    load_fields = sections.get("LOAD", "").split()
    if len(load_fields) == 3:
        load1, load5, load15 = (_parse_float(f) for f in load_fields)

    ram_used_bytes: int | None = None
    ram_total_bytes: int | None = None
    ram_fields = sections.get("RAM_KB", "").split()
    if len(ram_fields) == 2 and all(f.isdigit() for f in ram_fields):
        total_kb, used_kb = int(ram_fields[0]), int(ram_fields[1])
        ram_total_bytes = total_kb * 1024
        ram_used_bytes = used_kb * 1024

    network_io: list[dict[str, Any]] = []
    for line in sections.get("NET", "").splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit():
            network_io.append(
                {"iface": fields[0], "rx_bytes": int(fields[1]), "tx_bytes": int(fields[2])}
            )

    disk_io: list[dict[str, Any]] = []
    for line in sections.get("DISKIO", "").splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit():
            disk_io.append(
                {"device": fields[0], "read_bytes": int(fields[1]), "write_bytes": int(fields[2])}
            )

    filesystems: list[dict[str, Any]] = []
    for line in sections.get("FILESYSTEMS", "").splitlines():
        fields = line.split()
        # target size used avail pcent — same parsing as
        # app.ssh.facts.parse_facts_output (mount points rarely contain
        # spaces, but the last four fields are unambiguous either way).
        if len(fields) < 5:
            continue
        size, used, avail, pcent = fields[-4], fields[-3], fields[-2], fields[-1]
        target = " ".join(fields[:-4])
        if not (size.isdigit() and used.isdigit() and avail.isdigit()):
            continue
        filesystems.append(
            {
                "mount": target,
                "size_bytes": int(size),
                "used_bytes": int(used),
                "avail_bytes": int(avail),
                "use_percent": int(pcent.rstrip("%")) if pcent.rstrip("%").isdigit() else None,
            }
        )

    failed_services_count: int | None = None
    failed_line = sections.get("FAILED_SERVICES", "")
    if failed_line.isdigit():
        failed_services_count = int(failed_line)

    return MonitoringSample(
        cpu_percent=cpu_percent,
        load1=load1,
        load5=load5,
        load15=load15,
        ram_used_bytes=ram_used_bytes,
        ram_total_bytes=ram_total_bytes,
        network_io=network_io,
        disk_io=disk_io,
        filesystems=filesystems,
        failed_services_count=failed_services_count,
    )


async def gather_monitoring_sample(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> MonitoringSample:
    """Connect to a machine and take one CPU/load/RAM/network/disk-I/O/
    failed-services sample. Requires a pinned host key. `timeout_seconds`
    should comfortably exceed the `sleep 1` baked into `MONITORING_COMMAND`
    — the same `ssh_connect_timeout` every other SSH round trip in this
    app uses is already well above 1 second."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(MONITORING_COMMAND, check=False, timeout=timeout_seconds)

    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_monitoring_output(raw)
