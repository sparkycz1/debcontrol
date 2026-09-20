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

import json
import re
from typing import Any, TypedDict

from app.db.models.machine import Machine
from app.ssh.client import open_connection

_SECTION_MARKERS = ("CPU", "LOAD", "RAM_KB", "NET", "DISKIO", "FILESYSTEMS", "FAILED_SERVICES")

# Appended to MONITORING_COMMAND only for a machine with `is_physical`
# True (app.ssh.facts's systemd-detect-virt probe) — none of this is
# meaningful, and S.M.A.R.T. in particular actively misleading, against a
# virtual disk. Its own section markers, split the same way as the base
# command above.
_HARDWARE_SECTION_MARKERS = ("SENSORS", "SMART", "CPU_ENERGY_UJ", "GPU_POWER")

# SENSORS: `sensors -j` (lm-sensors, no root needed — reads hwmon sysfs
# directly) — parsed in Python (_parse_sensors_json) rather than the
# human-readable default output, since the JSON schema is documented and
# stable while the plain-text layout varies by chip/version.
#
# SMART: per-whole-disk (via `lsblk -d`, same tool the base command
# already uses) S.M.A.R.T. overall-health via smartctl -H — needs root on
# most systems (see app.ssh.onboarding's sudoers grant); `sudo -n`
# failing (no grant, or a hardened image with no usable sudo at all —
# same class of gap `app.ssh.readiness` already documents for dmidecode)
# just means that disk's health is never reported, not a crash.
#
# CPU_ENERGY_UJ: RAPL's own cumulative package-energy counter (microjoules
# since some arbitrary reference point, typically boot) — read as a plain
# gauge here, same as network/disk-I/O's cumulative byte counters; the
# *rate* (average watts) is computed downstream from consecutive samples
# (app.services.monitoring_history), not here, so this needs no extra
# sleep of its own. The glob covers both `intel-rapl:*` (Intel) and
# `amd-rapl:*` (AMD Zen 2+, kernel 5.8+, exposed the same way as Intel's
# once present) — a CPU with neither (older AMD, non-x86) is silently
# absent here, not an error.
#
# GPU_POWER: NVIDIA via `nvidia-smi`'s own instantaneous power draw —
# already a rate (watts), no downstream computation needed. AMD/Intel
# GPUs have no equivalent standalone CLI this app assumes is installed;
# their power draw (when the kernel driver exposes it — amdgpu always has,
# i915/xe only on newer kernels) comes through the same `sensors -j` dump
# SENSORS already captures, parsed by `_parse_sensors_json`'s power
# handling below, so nothing extra is added to this command for them.
_HARDWARE_COMMAND = (
    "echo ===SENSORS===; "
    "if command -v sensors >/dev/null 2>&1; then sensors -j 2>/dev/null; fi; "
    "echo ===SMART===; "
    "if command -v smartctl >/dev/null 2>&1; then "
    "for d in $(lsblk -d -n -o NAME,TYPE 2>/dev/null | awk '$2==\"disk\"{print $1}'); do "
    "status=\"$( (sudo -n smartctl -H /dev/$d 2>/dev/null || smartctl -H /dev/$d 2>/dev/null) "
    "| awk -F': ' '/overall-health/{print $2}')\"; "
    "if [ -n \"$status\" ]; then echo \"$d $status\"; fi; "
    "done; "
    "fi; "
    "echo ===CPU_ENERGY_UJ===; "
    "for f in /sys/class/powercap/*-rapl:*/energy_uj; do "
    "[ -f \"$f\" ] || continue; "
    "d=\"$(dirname \"$f\")\"; "
    "printf '%s ' \"$(cat \"$d/name\" 2>/dev/null || basename \"$d\")\"; "
    "cat \"$f\" 2>/dev/null || echo; "
    "done; "
    "echo ===GPU_POWER===; "
    "if command -v nvidia-smi >/dev/null 2>&1; then "
    "nvidia-smi --query-gpu=name,power.draw --format=csv,noheader,nounits 2>/dev/null; "
    "fi"
)

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
    # --- Hardware — only ever populated for a physical machine
    # (Machine.is_physical); always [] / None on a VM, meaning "not
    # applicable", not "nothing found". ---
    # Each {"name": ..., "celsius": ...}.
    sensor_temps: list[dict[str, Any]]
    # Each {"name": ..., "rpm": ...}.
    sensor_fans: list[dict[str, Any]]
    # Each {"device": ..., "healthy": bool | None} — None = smartctl ran
    # but its output didn't say PASSED/FAILED in the expected place.
    smart_disks: list[dict[str, Any]]
    # Cumulative RAPL package-energy counter, microjoules — see
    # _HARDWARE_COMMAND's own CPU_ENERGY_UJ comment for why this is a
    # counter here, not a rate.
    cpu_energy_uj: int | None
    # Already a rate (watts), not a counter — from nvidia-smi (NVIDIA) or,
    # falling back, the kernel driver's own hwmon power reading surfaced
    # through `sensors -j` (AMD/Intel) — see `_parse_sensors_json`.
    gpu_power_watts: float | None


def _split_sections(raw: str, markers: tuple[str, ...] = _SECTION_MARKERS) -> dict[str, str]:
    """Pairs chunks against `markers` positionally — the caller's raw
    output must carry every one of `markers` in that exact order (a
    trailing suffix can be missing, e.g. a connection that dropped
    mid-command, but not one skipped from the middle)."""
    pattern = "|".join(f"==={name}===" for name in markers)
    parts = re.split(f"(?:{pattern})", raw)
    body = parts[1:]
    return dict(zip(markers, (chunk.strip() for chunk in body), strict=False))


_FLOAT_RE = re.compile(r"^-?\d+(\.\d+)?$")


def _parse_float(value: str) -> float | None:
    return float(value) if _FLOAT_RE.match(value) else None


def parse_monitoring_output(raw: str, *, is_physical: bool = False) -> MonitoringSample:
    """Parse `MONITORING_COMMAND`'s output (plus `_HARDWARE_COMMAND`'s,
    appended in the same round trip when `is_physical`). Pure function, no
    I/O — kept separate from `gather_monitoring_sample` so it can be
    unit-tested against canned output, same convention as `app.ssh.facts.
    parse_facts_output`. The hardware section markers only ever appear in
    `raw` when the caller actually appended `_HARDWARE_COMMAND` (i.e.
    `is_physical` was true for *this* SSH round trip) — `is_physical`
    determines where `_split_sections` looks for them, not whether the
    command produced hardware output."""
    sections = _split_sections(raw)
    hardware_sections = (
        _split_sections(raw, _HARDWARE_SECTION_MARKERS) if is_physical else {}
    )

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
    # `.splitlines()[0]`, not the whole (stripped) chunk: when
    # `is_physical` appends `_HARDWARE_COMMAND` to the same round trip,
    # this first pass's own marker pattern doesn't recognize the hardware
    # markers, so this last base section's raw text runs straight into
    # everything after it (the hardware output is parsed out separately,
    # below, against its own marker set) — only the first line is ever
    # this section's own value.
    failed_lines = sections.get("FAILED_SERVICES", "").splitlines()
    failed_line = failed_lines[0] if failed_lines else ""
    if failed_line.isdigit():
        failed_services_count = int(failed_line)

    sensor_temps, sensor_fans, amd_intel_gpu_power_watts = _parse_sensors_json(
        hardware_sections.get("SENSORS", "")
    )
    smart_disks = _parse_smart(hardware_sections.get("SMART", ""))
    cpu_energy_uj = _parse_cpu_energy(hardware_sections.get("CPU_ENERGY_UJ", ""))
    # NVIDIA (nvidia-smi) tried first since it's the more precise,
    # purpose-built reading; AMD/Intel's sensors-derived one is the
    # fallback for whichever vendor's GPU is actually present. An explicit
    # `is not None` check (not `or`) since 0.0 W — an idle GPU — is a
    # genuine reading, not "missing".
    nvidia_gpu_power_watts = _parse_gpu_power(hardware_sections.get("GPU_POWER", ""))
    gpu_power_watts = (
        nvidia_gpu_power_watts
        if nvidia_gpu_power_watts is not None
        else amd_intel_gpu_power_watts
    )

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
        sensor_temps=sensor_temps,
        sensor_fans=sensor_fans,
        smart_disks=smart_disks,
        cpu_energy_uj=cpu_energy_uj,
        gpu_power_watts=gpu_power_watts,
    )


# Chip-name prefixes lm-sensors uses for the kernel drivers that expose a
# GPU's own power draw (as opposed to a CPU's, e.g. `k10temp` never has
# one) — `amdgpu` (AMD, always has one when the driver's loaded), `i915`/
# `xe` (Intel, only on kernels new enough to register the hwmon power
# reading). NVIDIA's proprietary driver never registers here — that's
# `_parse_gpu_power`'s `nvidia-smi` job instead, tried first by the caller.
_GPU_SENSOR_CHIP_PREFIXES = ("amdgpu", "i915", "xe")


def _parse_sensors_json(
    raw: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], float | None]:
    """`sensors -j`'s shape: `{chip: {"Adapter": "...", feature_label: {key:
    value, ...}, ...}, ...}` — every `*_input` reading under a feature
    whose key starts with `temp`/`fan` is one temperature/fan reading,
    labeled with that feature's own name (e.g. "Core 0", "fan1"), not the
    chip name — the chip is an implementation detail (which sensor chip
    happens to expose it), the feature label is what a human would
    recognize. A `power`-prefixed reading under a GPU chip (see
    `_GPU_SENSOR_CHIP_PREFIXES`) is this machine's AMD/Intel GPU power
    draw, already in watts (lm-sensors' own JSON, unlike raw sysfs
    microwatts) — first one found, same "one representative reading"
    scope `_parse_gpu_power` already has for NVIDIA. Malformed/empty input
    (not JSON, no `sensors` binary, unexpected shape) yields empty/None
    rather than raising — a monitoring sample must never fail outright
    over an optional reading."""
    temps: list[dict[str, Any]] = []
    fans: list[dict[str, Any]] = []
    gpu_power_watts: float | None = None
    if not raw.strip():
        return temps, fans, gpu_power_watts
    try:
        chips = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return temps, fans, gpu_power_watts
    if not isinstance(chips, dict):
        return temps, fans, gpu_power_watts

    for chip_name, features in chips.items():
        if not isinstance(features, dict):
            continue
        is_gpu_chip = isinstance(chip_name, str) and chip_name.startswith(
            _GPU_SENSOR_CHIP_PREFIXES
        )
        for label, readings in features.items():
            if label == "Adapter" or not isinstance(readings, dict):
                continue
            for key, value in readings.items():
                if not isinstance(value, (int, float)):
                    continue
                if key.endswith("_input") and key.startswith("temp"):
                    temps.append({"name": label, "celsius": float(value)})
                elif key.endswith("_input") and key.startswith("fan"):
                    fans.append({"name": label, "rpm": float(value)})
                elif is_gpu_chip and gpu_power_watts is None and key.startswith("power"):
                    gpu_power_watts = float(value)
    return temps, fans, gpu_power_watts


def _parse_smart(raw: str) -> list[dict[str, Any]]:
    """Each line is `<device> <PASSED|FAILED|...>` (see _HARDWARE_COMMAND's
    own SMART awk extraction). Anything other than a literal "PASSED"/
    "FAILED" (a truncated/unexpected smartctl message) is recorded as
    `healthy: None` — "ran, but couldn't tell" — rather than guessed at."""
    disks: list[dict[str, Any]] = []
    for line in raw.splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            continue
        device, status = fields
        if status == "PASSED":
            healthy: bool | None = True
        elif status == "FAILED":
            healthy = False
        else:
            healthy = None
        disks.append({"device": device, "healthy": healthy})
    return disks


def _parse_cpu_energy(raw: str) -> int | None:
    """First RAPL domain found (typically the CPU package as a whole,
    `package-0` — see _HARDWARE_COMMAND) whose energy_uj value parsed as a
    whole number; further domains (per-core, DRAM, ...) aren't summed in,
    to avoid double-counting a sub-domain that's already part of the
    package total."""
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit():
            return int(fields[1])
    return None


def _parse_gpu_power(raw: str) -> float | None:
    """`nvidia-smi --query-gpu=name,power.draw --format=csv,noheader,
    nounits` — first GPU's power draw in watts, already a rate (not a
    counter, unlike CPU_ENERGY_UJ). Multiple GPUs report multiple lines;
    only the first is kept — same "one representative reading, not a
    per-device breakdown" scope as the rest of this first version."""
    for line in raw.splitlines():
        fields = [f.strip() for f in line.split(",")]
        if len(fields) == 2:
            watts = _parse_float(fields[1])
            if watts is not None:
                return watts
    return None


async def gather_monitoring_sample(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> MonitoringSample:
    """Connect to a machine and take one CPU/load/RAM/network/disk-I/O/
    failed-services sample — plus, only when `machine.is_physical`,
    hardware sensors/fans/S.M.A.R.T./power draw (see _HARDWARE_COMMAND).
    Requires a pinned host key. `timeout_seconds` should comfortably
    exceed the `sleep 1` baked into `MONITORING_COMMAND` — the same
    `ssh_connect_timeout` every other SSH round trip in this app uses is
    already well above 1 second."""
    is_physical = bool(machine.is_physical)
    command = f"{MONITORING_COMMAND}; {_HARDWARE_COMMAND}" if is_physical else MONITORING_COMMAND
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(command, check=False, timeout=timeout_seconds)

    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_monitoring_output(raw, is_physical=is_physical)
