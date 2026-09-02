"""Gather one CPU/RAM/disk-usage sample from a managed machine — the
Monitoring tab's trend graphs. Read-only, no root needed for any of it
(same convention as `app.ssh.facts`).

Deliberately its own, much lighter, round trip than `app.ssh.facts` — this
runs on a much shorter cadence (`MONITORING_INTERVAL_SECONDS`, 2 minutes by
default, vs. facts' 1 hour), so it only gathers what a frequent sample
actually needs: CPU/RAM/disk usage right now, plus a cheap *count* of
failed systemd services (the full unit list is `app.ssh.services`, on the
facts cadence instead — see that module's own docstring for why).
"""

from __future__ import annotations

import re
from typing import Any, TypedDict

from app.db.models.machine import Machine
from app.ssh.client import open_connection

_SECTION_MARKERS = ("CPU", "RAM_KB", "DISKS", "FAILED_SERVICES")

# CPU percent needs two samples of /proc/stat a moment apart — computed
# entirely in the one round trip (a 1-second `sleep`) rather than as two
# separate SSH round trips, so this whole command still only takes about a
# second longer than a plain connect. POSIX `read` (works in `sh`/`dash`,
# Debian's default `/bin/sh`) splits the line into the named fields;
# `awk` does the float-safe percentage math `sh` arithmetic can't.
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
    "echo ===RAM_KB===; "
    "awk '/MemTotal/ {total=$2} /MemAvailable/ {avail=$2} "
    "END { if (total > 0) printf \"%d %d\\n\", total, total-avail }' "
    "/proc/meminfo 2>/dev/null; "
    "echo ===DISKS===; "
    "df -B1 --output=target,pcent -x tmpfs -x devtmpfs -x squashfs -x overlay "
    "2>/dev/null | tail -n +2; "
    "echo ===FAILED_SERVICES===; "
    "if command -v systemctl >/dev/null 2>&1; then "
    "systemctl --failed --plain --no-legend --no-pager 2>/dev/null | wc -l; "
    "fi"
)


class MonitoringSample(TypedDict):
    cpu_percent: float | None
    ram_used_bytes: int | None
    ram_total_bytes: int | None
    disks: list[dict[str, Any]]
    # None = couldn't tell (no systemd), not "zero failed".
    failed_services_count: int | None


def _split_sections(raw: str) -> dict[str, str]:
    pattern = "|".join(f"==={name}===" for name in _SECTION_MARKERS)
    parts = re.split(f"(?:{pattern})", raw)
    body = parts[1:]
    return dict(zip(_SECTION_MARKERS, (chunk.strip() for chunk in body), strict=False))


_FLOAT_RE = re.compile(r"^-?\d+(\.\d+)?$")


def parse_monitoring_output(raw: str) -> MonitoringSample:
    """Parse `MONITORING_COMMAND`'s output. Pure function, no I/O — kept
    separate from `gather_monitoring_sample` so it can be unit-tested
    against canned output, same convention as `app.ssh.facts.
    parse_facts_output`."""
    sections = _split_sections(raw)

    cpu_percent: float | None = None
    cpu_line = sections.get("CPU", "")
    if _FLOAT_RE.match(cpu_line):
        cpu_percent = float(cpu_line)

    ram_used_bytes: int | None = None
    ram_total_bytes: int | None = None
    ram_fields = sections.get("RAM_KB", "").split()
    if len(ram_fields) == 2 and all(f.isdigit() for f in ram_fields):
        total_kb, used_kb = int(ram_fields[0]), int(ram_fields[1])
        ram_total_bytes = total_kb * 1024
        ram_used_bytes = used_kb * 1024

    disks: list[dict[str, Any]] = []
    for line in sections.get("DISKS", "").splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        pcent = fields[-1]
        mount = " ".join(fields[:-1])
        if pcent.rstrip("%").isdigit():
            disks.append({"mount": mount, "use_percent": int(pcent.rstrip("%"))})

    failed_services_count: int | None = None
    failed_line = sections.get("FAILED_SERVICES", "")
    if failed_line.isdigit():
        failed_services_count = int(failed_line)

    return MonitoringSample(
        cpu_percent=cpu_percent,
        ram_used_bytes=ram_used_bytes,
        ram_total_bytes=ram_total_bytes,
        disks=disks,
        failed_services_count=failed_services_count,
    )


async def gather_monitoring_sample(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> MonitoringSample:
    """Connect to a machine and take one CPU/RAM/disk/failed-services
    sample. Requires a pinned host key. `timeout_seconds` should comfortably
    exceed the `sleep 1` baked into `MONITORING_COMMAND` — the same
    `ssh_connect_timeout` every other SSH round trip in this app uses is
    already well above 1 second."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(MONITORING_COMMAND, check=False, timeout=timeout_seconds)

    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_monitoring_output(raw)
