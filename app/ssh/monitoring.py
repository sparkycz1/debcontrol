"""Gather one monitoring sample from a managed machine — the Monitoring
tab's trend graphs. Read-only; nothing here strictly needs root (S.M.A.R.T.
health and Docker access use a scoped `sudo -n` grant when one exists, and
are simply skipped when it doesn't).

Deliberately its own, much lighter, round trip than `app.ssh.facts` — this
runs on a much shorter cadence (`MONITORING_INTERVAL_SECONDS`, 2 minutes by
default, vs. facts' default 10 minutes), so it only gathers what a
frequent sample actually needs: CPU/load/RAM/network/disk-I/O/filesystem
usage right now, a cheap *count* of failed systemd services (the full unit
list, with per-service CPU/memory, is `app.ssh.services`, on the facts
cadence), Docker container stats when Docker is present, and — on a
physical machine only — hardware sensors/fans/S.M.A.R.T. health/power/GPUs.

Filesystem usage (`df`, same command `app.ssh.facts` already runs) *is*
gathered here too, on this shorter cadence, precisely so the Monitoring
tab can show a *history* of how full a mount is over time.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any, TypedDict

from app.db.models.machine import Machine
from app.ssh import proxmox
from app.ssh.pool import machine_connection
from app.ssh.shell import with_root_shim

_SECTION_MARKERS = (
    "CPU",
    "LOAD",
    "RAM_KB",
    "NET",
    "DISKIO",
    "FILESYSTEMS",
    "FAILED_SERVICES",
    "DOCKER",
    "ZFS_ARC",
    *proxmox.LIVE_MARKERS,
)

# Appended to MONITORING_COMMAND only for a machine with `is_physical`
# True (app.ssh.facts's systemd-detect-virt probe) — none of this is
# meaningful, and S.M.A.R.T. in particular actively misleading, against a
# virtual disk.
_HARDWARE_SECTION_MARKERS = ("SENSORS", "SMART", "CPU_ENERGY_UJ", "GPUS")

_ALL_MARKERS = frozenset(_SECTION_MARKERS + _HARDWARE_SECTION_MARKERS)
_MARKER_RE = re.compile(r"^===([A-Z_]+)===[ \t]*$", re.MULTILINE)

# SENSORS: `sensors -j` (lm-sensors, no root needed — reads hwmon sysfs
# directly) — parsed in Python (_parse_sensors_json) rather than the
# human-readable default output, since the JSON schema is documented and
# stable while the plain-text layout varies by chip/version.
#
# SMART: per-whole-disk overall-health via smartctl -H — needs root on
# most systems (see app.ssh.onboarding's sudoers grant); no grant just
# means that disk's health is never reported, not a crash. The full
# attribute dump (model, hours, cycles, ...) is gathered with facts
# instead — see app.ssh.smart.
#
# CPU_ENERGY_UJ: RAPL's own cumulative package-energy counter (microjoules)
# — read as a plain gauge here, same as network/disk-I/O's cumulative
# byte counters; the *rate* (average watts) is computed downstream from
# consecutive samples (app.services.monitoring_history). The glob covers
# both `intel-rapl:*` (Intel) and `amd-rapl:*` (AMD Zen 2+, kernel 5.8+).
#
# GPUS: one tab-separated line per GPU. NVIDIA via `nvidia-smi` (MiB,
# watts); AMD/Intel via the DRM driver's own sysfs files — `gpu_busy_percent`
# and `mem_info_vram_*` (amdgpu; i915/xe expose neither), and the hwmon
# `power1_average`/`power1_input` reading in microwatts when the driver
# registers one. NVIDIA DRM entries are skipped there (nvidia-smi already
# covers them). The card's name comes from its own `product_name` file
# when present, else `lspci -mm` for that PCI slot, else just the card id.
_HARDWARE_COMMAND = (
    "echo ===SENSORS===; "
    "if command -v sensors >/dev/null 2>&1; then sensors -j 2>/dev/null; fi; "
    "echo ===SMART===; "
    "if command -v smartctl >/dev/null 2>&1; then "
    "for d in $(lsblk -d -n -o NAME,TYPE 2>/dev/null | awk '$2==\"disk\"{print $1}'); do "
    "status=\"$( (sudo -n smartctl -H /dev/$d 2>/dev/null || smartctl -H /dev/$d 2>/dev/null) "
    "| awk -F': ' '/overall-health/{print $2; exit}')\"; "
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
    "echo ===GPUS===; "
    "if command -v nvidia-smi >/dev/null 2>&1; then "
    "nvidia-smi --query-gpu=index,utilization.gpu,memory.used,memory.total,power.draw,name "
    "--format=csv,noheader,nounits 2>/dev/null "
    "| awk -F', *' '{printf \"nvidia\\t%s\\t\\t%s\\t%s\\t%s\\t%s\\t%s\\n\", "
    "$1, $2, $3, $4, $5, $6}'; "
    "fi; "
    "for c in /sys/class/drm/card[0-9]*; do "
    "case \"${c##*/}\" in *-*) continue;; esac; "
    "d=\"$c/device\"; [ -r \"$d/vendor\" ] || continue; "
    "v=\"$(cat \"$d/vendor\" 2>/dev/null)\"; [ \"$v\" = 0x10de ] && continue; "
    "b=\"$(cat \"$d/gpu_busy_percent\" 2>/dev/null)\"; "
    "u=\"$(cat \"$d/mem_info_vram_used\" 2>/dev/null)\"; "
    "t=\"$(cat \"$d/mem_info_vram_total\" 2>/dev/null)\"; "
    "p=\"$(cat \"$d\"/hwmon/hwmon*/power1_average 2>/dev/null | head -n1)\"; "
    "[ -n \"$p\" ] || p=\"$(cat \"$d\"/hwmon/hwmon*/power1_input 2>/dev/null | head -n1)\"; "
    "n=\"$(cat \"$d/product_name\" 2>/dev/null)\"; "
    "if [ -z \"$n\" ] && command -v lspci >/dev/null 2>&1; then "
    "n=\"$(lspci -mm -s \"$(basename \"$(readlink -f \"$d\")\")\" 2>/dev/null | head -n1)\"; "
    "fi; "
    "printf 'drm\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "
    "\"${c##*/}\" \"$v\" \"$b\" \"$u\" \"$t\" \"$p\" \"$n\"; "
    "done"
)

# CPU percent needs two samples of /proc/stat a moment apart — computed
# entirely in the one round trip (a 1-second `sleep`) rather than as two
# separate SSH round trips. POSIX `read` (works in `sh`/`dash`, Debian's
# default `/bin/sh`) splits the line into the named fields; `awk` does the
# float-safe percentage math `sh` arithmetic can't.
#
# NET: `/proc/net/dev`'s own column layout — `face: rx_bytes rx_packets
# ... tx_bytes ...` (fields 2 and 10). `lo` is skipped. Cumulative counters
# since boot; the *rate* is computed later from consecutive samples
# (`app.services.monitoring_history`), not here.
#
# DISKIO: `/proc/diskstats`'s `sectors_read`/`sectors_written` columns
# (fields 6 and 10; 512-byte sectors, the kernel's own fixed unit) filtered
# down to whole disks only (via `lsblk -d`) — a partition's numbers would
# otherwise double-count against its parent disk's.
#
# DOCKER: only when a `docker` CLI exists. Plain `docker` first (the
# account is in the `docker` group), else `sudo -n docker` when a sudoers
# rule allows exactly that binary (`sudo -n -l <path>` asks without
# prompting); neither → `@@NOACCESS`, reported as such rather than as "no
# containers". `ps -a` gives the table (image/state/status/ports), `stats
# --no-stream` the CPU/memory. Network bytes come from each container's
# own network namespace (`/proc/<pid>/net/dev`, exact counters) rather
# than `stats`' rounded, human-readable NetIO — which is only the fallback
# when that file isn't readable. Host-network containers are skipped
# there, since their namespace *is* the host's.
_DOCKER_COMMAND = (
    "echo ===DOCKER===; "
    "if command -v docker >/dev/null 2>&1; then "
    "D=docker; "
    "if ! docker ps -q >/dev/null 2>&1; then "
    "DP=\"$(command -v docker)\"; "
    "if sudo -n -l \"$DP\" >/dev/null 2>&1; then D=\"sudo -n $DP\"; else D=; fi; "
    "fi; "
    "if [ -z \"$D\" ]; then echo @@NOACCESS; else "
    "echo @@PS; $D ps -a --no-trunc --format '{{json .}}' 2>/dev/null; "
    "echo @@STATS; $D stats --no-stream --no-trunc --format '{{json .}}' 2>/dev/null; "
    "echo @@NET; ids=\"$($D ps -q 2>/dev/null)\"; "
    "if [ -n \"$ids\" ]; then "
    "$D inspect -f '{{.Name}} {{.State.Pid}} {{.HostConfig.NetworkMode}}' $ids 2>/dev/null "
    "| while read -r n p m; do "
    "[ \"$m\" = host ] && continue; [ -r \"/proc/$p/net/dev\" ] || continue; "
    "awk -v n=\"${n#/}\" 'NR>2 {gsub(\":\", \" \"); if ($1 != \"lo\") {rx+=$2; tx+=$10}} "
    "END {printf \"%s %.0f %.0f\\n\", n, rx, tx}' \"/proc/$p/net/dev\" 2>/dev/null; "
    "done; "
    "fi; "
    "fi; "
    "fi"
)

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
    # total, used (total - available) and buff/cache (what `free` shows).
    "echo ===RAM_KB===; "
    "awk '/^MemTotal:/ {total=$2} /^MemAvailable:/ {avail=$2} /^Buffers:/ {buf=$2} "
    "/^Cached:/ {cached=$2} /^SReclaimable:/ {srec=$2} "
    "END { if (total > 0) printf \"%d %d %d\\n\", total, total-avail, buf+cached+srec }' "
    "/proc/meminfo 2>/dev/null; "
    # The ZFS ARC's current size (bytes). The kernel doesn't count it as
    # "available" memory, so on a ZFS host it would otherwise all show up
    # as used — see parse_monitoring_output.
    "echo ===ZFS_ARC===; "
    "awk '$1 == \"size\" {print $3; exit}' /proc/spl/kstat/zfs/arcstats 2>/dev/null; "
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
    # `@@OK` first — telling "systemd, nothing failed" apart from "no
    # systemd" — then one failed unit name per line.
    "echo ===FAILED_SERVICES===; "
    "if command -v systemctl >/dev/null 2>&1; then echo @@OK; "
    "systemctl --failed --plain --no-legend --no-pager 2>/dev/null | awk '{print $1}'; "
    "fi; "
    f"{_DOCKER_COMMAND}; "
    f"{proxmox.LIVE_COMMAND}"
)


class MonitoringSample(TypedDict):
    cpu_percent: float | None
    # 1/5/15-minute load averages (`/proc/loadavg`).
    load1: float | None
    load5: float | None
    load15: float | None
    # Used by processes — total minus available, minus the ZFS ARC.
    ram_used_bytes: int | None
    ram_total_bytes: int | None
    # ZFS ARC size (None = no ZFS) and the page cache/buffers — both give
    # memory back under pressure, charted apart from `ram_used_bytes`.
    ram_arc_bytes: int | None
    ram_cache_bytes: int | None
    # Latest ZFS pools / Proxmox VE guests (app.ssh.proxmox), None = none.
    zfs_pools: list[dict[str, Any]] | None
    pve_guests: list[dict[str, Any]] | None
    pve_cluster: dict[str, Any] | None
    # Each {"iface": ..., "rx_bytes": ..., "tx_bytes": ...} — cumulative
    # counters since boot, one entry per non-loopback interface found.
    network_io: list[dict[str, Any]]
    # Each {"device": ..., "read_bytes": ..., "write_bytes": ...} —
    # cumulative counters since boot, one entry per whole disk found.
    disk_io: list[dict[str, Any]]
    # Each {"mount", "size_bytes", "used_bytes", "avail_bytes", "use_percent"}.
    filesystems: list[dict[str, Any]]
    # None = couldn't tell (no systemd), not "zero failed".
    failed_services_count: int | None
    # The failed units' names (None = couldn't tell).
    failed_units: list[str] | None
    # None = no docker CLI at all; "no_access" = present but this account
    # can't talk to the daemon; "ok" = `docker_containers` is authoritative.
    docker_status: str | None
    # Each {"name", "image", "state", "status", "health", "ports",
    # "cpu_percent", "mem_bytes", "mem_limit_bytes", "net_rx_bytes",
    # "net_tx_bytes"} — every container `docker ps -a` lists, stats only
    # for running ones (None otherwise). Net bytes are cumulative since the
    # container started.
    docker_containers: list[dict[str, Any]]
    # --- Hardware — only ever populated for a physical machine
    # (Machine.is_physical); always [] / None on a VM, meaning "not
    # applicable", not "nothing found". ---
    sensor_temps: list[dict[str, Any]]
    sensor_fans: list[dict[str, Any]]
    # Each {"device": ..., "healthy": bool | None}.
    smart_disks: list[dict[str, Any]]
    # Cumulative RAPL package-energy counter, microjoules.
    cpu_energy_uj: int | None
    # Each {"id", "name", "vendor", "util_percent", "vram_used_bytes",
    # "vram_total_bytes", "power_watts"} — any metric the driver doesn't
    # expose is None.
    gpus: list[dict[str, Any]]
    # Sum of every GPU's power draw (watts), falling back to an AMD/Intel
    # GPU chip's hwmon reading in `sensors -j` — see `_parse_sensors_json`.
    gpu_power_watts: float | None


def _split_sections(raw: str, markers: tuple[str, ...] = _SECTION_MARKERS) -> dict[str, str]:
    """`{name: text}` for each of `markers` present in `raw`, matched by
    *name* — every known marker (base, Docker and hardware alike) ends the
    section before it, whichever of them this particular call asked for,
    so a section missing from the middle (or trailing text from a command
    appended to the same round trip) never shifts another section's
    content."""
    wanted = set(markers)
    matches = [m for m in _MARKER_RE.finditer(raw) if m.group(1) in _ALL_MARKERS]
    sections: dict[str, str] = {}
    for i, match in enumerate(matches):
        name = match.group(1)
        end = matches[i + 1].start() if i + 1 < len(matches) else len(raw)
        if name in wanted and name not in sections:
            sections[name] = raw[match.end() : end].strip()
    return sections


_FLOAT_RE = re.compile(r"^-?\d+(\.\d+)?$")


def _parse_float(value: str) -> float | None:
    return float(value) if _FLOAT_RE.match(value.strip()) else None


def parse_monitoring_output(raw: str, *, is_physical: bool = False) -> MonitoringSample:
    """Parse `MONITORING_COMMAND`'s output (plus `_HARDWARE_COMMAND`'s,
    appended in the same round trip when `is_physical`). Pure function, no
    I/O — kept separate from `gather_monitoring_sample` so it can be
    unit-tested against canned output."""
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
    ram_cache_bytes: int | None = None
    arc_text = sections.get("ZFS_ARC", "").strip()
    ram_arc_bytes = int(arc_text) if arc_text.isdigit() else None
    ram_fields = sections.get("RAM_KB", "").split()
    if len(ram_fields) in (2, 3) and all(f.isdigit() for f in ram_fields):
        total_kb, used_kb = int(ram_fields[0]), int(ram_fields[1])
        ram_total_bytes = total_kb * 1024
        ram_used_bytes = used_kb * 1024
        if ram_arc_bytes:
            # The ARC shrinks on demand like the page cache does; counting
            # it as "used" made a ZFS host look nearly full all the time.
            ram_used_bytes = max(0, ram_used_bytes - ram_arc_bytes)
        if len(ram_fields) == 3:
            ram_cache_bytes = int(ram_fields[2]) * 1024

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
        # target size used avail pcent — the last four fields are
        # unambiguous even if a mount point contains a space.
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
    failed_units: list[str] | None = None
    failed_lines = [
        line.strip() for line in sections.get("FAILED_SERVICES", "").splitlines() if line.strip()
    ]
    if failed_lines and failed_lines[0] == "@@OK":
        failed_units = sorted(set(failed_lines[1:]))
        failed_services_count = len(failed_units)
    elif len(failed_lines) == 1 and failed_lines[0].isdigit():
        # The older `wc -l` form.
        failed_services_count = int(failed_lines[0])

    docker_status, docker_containers = _parse_docker(sections.get("DOCKER"))

    sensor_temps, sensor_fans, sensor_gpu_power_watts = _parse_sensors_json(
        hardware_sections.get("SENSORS", "")
    )
    smart_disks = _parse_smart(hardware_sections.get("SMART", ""))
    cpu_energy_uj = _parse_cpu_energy(hardware_sections.get("CPU_ENERGY_UJ", ""))
    gpus = _parse_gpus(hardware_sections.get("GPUS", ""))

    gpu_powers = [g["power_watts"] for g in gpus if g["power_watts"] is not None]
    gpu_power_watts = round(sum(gpu_powers), 2) if gpu_powers else sensor_gpu_power_watts

    return MonitoringSample(
        cpu_percent=cpu_percent,
        load1=load1,
        load5=load5,
        load15=load15,
        ram_used_bytes=ram_used_bytes,
        ram_total_bytes=ram_total_bytes,
        ram_arc_bytes=ram_arc_bytes,
        ram_cache_bytes=ram_cache_bytes,
        zfs_pools=proxmox.parse_zfs_pools(
            sections.get("ZFS_POOLS", ""), sections.get("ZFS_STATUS", "")
        ),
        pve_guests=proxmox.parse_guests(sections.get("PVE_GUESTS", "")),
        pve_cluster=proxmox.parse_cluster(sections.get("PVE_CLUSTER", "")),
        network_io=network_io,
        disk_io=disk_io,
        filesystems=filesystems,
        failed_services_count=failed_services_count,
        failed_units=failed_units,
        docker_status=docker_status,
        docker_containers=docker_containers,
        sensor_temps=sensor_temps,
        sensor_fans=sensor_fans,
        smart_disks=smart_disks,
        cpu_energy_uj=cpu_energy_uj,
        gpus=gpus,
        gpu_power_watts=gpu_power_watts,
    )


# Chip-name prefixes lm-sensors uses for the kernel drivers that expose a
# GPU's own power draw — `amdgpu` (AMD), `i915`/`xe` (Intel, newer kernels).
_GPU_SENSOR_CHIP_PREFIXES = ("amdgpu", "i915", "xe")


def _sensor_label(chip_name: str, label: str) -> str:
    """A reading's display name — the feature label alone is ambiguous
    across chips (every NVMe drive has its own "Composite", every hwmon
    driver its own "temp1"), so it's prefixed with the chip's driver name
    (`nvme-pci-0100` → "nvme") unless the label already says which device
    it is."""
    driver = chip_name.split("-", 1)[0]
    if not driver or label.lower().startswith(driver.lower()):
        return label
    return f"{driver} {label}"


def _parse_sensors_json(
    raw: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], float | None]:
    """`sensors -j`'s shape: `{chip: {"Adapter": "...", feature_label: {key:
    value, ...}, ...}, ...}` — every `*_input` reading under a feature
    whose key starts with `temp`/`fan` is one temperature/fan reading. A
    `power`-prefixed reading under a GPU chip (see
    `_GPU_SENSOR_CHIP_PREFIXES`) is an AMD/Intel GPU's power draw, already
    in watts. A name repeated across chips/features gets a numeric suffix
    so every series stays distinct. Malformed/empty input yields empty/None
    rather than raising — a sample must never fail over an optional
    reading."""
    temps: list[dict[str, Any]] = []
    fans: list[dict[str, Any]] = []
    gpu_power_watts: float | None = None
    if not raw.strip():
        return temps, fans, gpu_power_watts
    try:
        chips = json.loads(raw)
    except (ValueError, RecursionError):  # RecursionError: absurdly nested JSON
        return temps, fans, gpu_power_watts
    if not isinstance(chips, dict):
        return temps, fans, gpu_power_watts

    seen: dict[str, int] = {}

    def unique(name: str) -> str:
        count = seen.get(name, 0) + 1
        seen[name] = count
        return name if count == 1 else f"{name} ({count})"

    for chip_name, features in chips.items():
        if not isinstance(features, dict) or not isinstance(chip_name, str):
            continue
        is_gpu_chip = chip_name.startswith(_GPU_SENSOR_CHIP_PREFIXES)
        for label, readings in features.items():
            if label == "Adapter" or not isinstance(readings, dict):
                continue
            for key, value in readings.items():
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    continue
                if key.endswith("_input") and key.startswith("temp"):
                    temps.append(
                        {"name": unique(_sensor_label(chip_name, label)), "celsius": float(value)}
                    )
                elif key.endswith("_input") and key.startswith("fan"):
                    fans.append(
                        {"name": unique(_sensor_label(chip_name, label)), "rpm": float(value)}
                    )
                elif is_gpu_chip and gpu_power_watts is None and key.startswith("power"):
                    gpu_power_watts = float(value)
    return temps, fans, gpu_power_watts


def _parse_smart(raw: str) -> list[dict[str, Any]]:
    """Each line is `<device> <PASSED|FAILED|...>`. Anything other than a
    literal "PASSED"/"OK"/"FAILED" is `healthy: None` — "ran, but couldn't
    tell" — rather than guessed at."""
    disks: list[dict[str, Any]] = []
    for line in raw.splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            continue
        device, status = fields
        status = status.strip()
        healthy: bool | None
        if status in ("PASSED", "OK"):
            healthy = True
        elif status.startswith("FAILED"):
            healthy = False
        else:
            healthy = None
        disks.append({"device": device, "healthy": healthy})
    return disks


def _parse_cpu_energy(raw: str) -> int | None:
    """Sum of every top-level RAPL *package* domain (`package-0`,
    `package-1` on a dual-socket board) — sub-domains (core, uncore, dram)
    are already part of a package's own total, so they're not added in.
    Falls back to the first domain of any name when none is called
    `package-*` (some AMD kernels name it differently)."""
    packages: list[int] = []
    first: int | None = None
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[1].isdigit():
            continue
        value = int(fields[1])
        if first is None:
            first = value
        if fields[0].startswith("package"):
            packages.append(value)
    return sum(packages) if packages else first


_GPU_VENDORS = {"0x1002": "amd", "0x8086": "intel", "0x10de": "nvidia"}
_GPU_VENDOR_PREFIX = {"amd": "AMD", "intel": "Intel", "nvidia": "NVIDIA"}
_BRACKETED_RE = re.compile(r"\[([^\]]+)\]")


def _gpu_display_name(raw_name: str, vendor: str, card_id: str) -> str:
    """`product_name`'s own text is used as-is. An `lspci -mm` line
    (`slot "class" "vendor" "device" ...`) is reduced to its device field —
    and to the marketing name in brackets when there is one (`Lexa PRO
    [Radeon RX 550]` → `Radeon RX 550`) — prefixed with the vendor."""
    name = raw_name.strip()
    if not name:
        return card_id
    if name.count('"') >= 6:
        try:
            tokens = shlex.split(name)
        except ValueError:
            tokens = []
        if len(tokens) >= 4:
            name = tokens[3]
            bracketed = _BRACKETED_RE.search(name)
            if bracketed:
                name = bracketed.group(1)
    prefix = _GPU_VENDOR_PREFIX.get(vendor)
    if prefix and not name.lower().startswith(prefix.lower()):
        name = f"{prefix} {name}"
    return name


def _int_or_none(value: str) -> int | None:
    value = value.strip()
    return int(value) if value.isdigit() else None


def _parse_gpus(raw: str) -> list[dict[str, Any]]:
    gpus: list[dict[str, Any]] = []
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        kind, card_id, vendor_id, busy, used, total, power, name = fields[:8]
        if kind == "nvidia":
            used_mib, total_mib = _parse_float(used), _parse_float(total)
            gpu = {
                "id": f"nvidia{card_id.strip()}",
                "vendor": "nvidia",
                "util_percent": _parse_float(busy),
                "vram_used_bytes": int(used_mib * 1048576) if used_mib is not None else None,
                "vram_total_bytes": int(total_mib * 1048576) if total_mib is not None else None,
                "power_watts": _parse_float(power),
            }
            raw_name = name
        elif kind == "drm":
            vendor = _GPU_VENDORS.get(vendor_id.strip().lower())
            if vendor is None:
                continue  # an emulated/virtual display adapter, not a GPU
            power_uw = _int_or_none(power)
            gpu = {
                "id": card_id.strip(),
                "vendor": vendor,
                "util_percent": _parse_float(busy),
                "vram_used_bytes": _int_or_none(used),
                "vram_total_bytes": _int_or_none(total),
                "power_watts": round(power_uw / 1_000_000, 2) if power_uw is not None else None,
            }
            raw_name = name
        else:
            continue
        if all(
            gpu[k] is None
            for k in ("util_percent", "vram_used_bytes", "vram_total_bytes", "power_watts")
        ):
            continue  # nothing measurable — e.g. an Intel iGPU on an older kernel
        gpu["name"] = _gpu_display_name(raw_name, str(gpu["vendor"]), str(gpu["id"]))
        gpus.append(gpu)
    return gpus


_SIZE_RE = re.compile(r"^\s*([\d.]+)\s*([A-Za-z]*)\s*$")
_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}


def _parse_size(value: str) -> int | None:
    """Docker's human-readable sizes: `172MiB` (binary) or `66kB` (decimal)."""
    match = _SIZE_RE.match(value or "")
    if not match:
        return None
    multiplier = _SIZE_UNITS.get(match.group(2).lower())
    if multiplier is None:
        return None
    try:
        return int(float(match.group(1)) * multiplier)
    except ValueError:
        return None


def _parse_percent(value: str | None) -> float | None:
    if not value:
        return None
    return _parse_float(value.strip().rstrip("%"))


def _container_health(status: str) -> str | None:
    lowered = status.lower()
    if "(unhealthy)" in lowered:
        return "unhealthy"
    if "(healthy)" in lowered:
        return "healthy"
    if "health: starting" in lowered:
        return "starting"
    return None


def _parse_docker(raw: str | None) -> tuple[str | None, list[dict[str, Any]]]:
    """`(status, containers)` — see `MonitoringSample.docker_status`."""
    if raw is None or not raw.strip():
        return None, []
    if "@@NOACCESS" in raw:
        return "no_access", []

    blocks: dict[str, list[str]] = {"@@PS": [], "@@STATS": [], "@@NET": []}
    current: list[str] | None = None
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped in blocks:
            current = blocks[stripped]
        elif current is not None and stripped:
            current.append(stripped)

    def json_rows(lines: list[str]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for line in lines:
            try:
                row = json.loads(line)
            except (ValueError, RecursionError):  # RecursionError: absurdly nested JSON
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows

    stats_by_name = {
        str(row.get("Name", "")).lstrip("/"): row for row in json_rows(blocks["@@STATS"])
    }
    net_by_name: dict[str, tuple[int, int]] = {}
    for line in blocks["@@NET"]:
        fields = line.split()
        if len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit():
            net_by_name[fields[0]] = (int(fields[1]), int(fields[2]))

    containers: list[dict[str, Any]] = []
    for row in json_rows(blocks["@@PS"]):
        name = str(row.get("Names", "")).split(",")[0].lstrip("/")
        if not name:
            continue
        status = str(row.get("Status", ""))
        stats = stats_by_name.get(name)
        cpu_percent = mem_bytes = mem_limit = net_rx = net_tx = None
        if stats is not None:
            cpu_percent = _parse_percent(stats.get("CPUPerc"))
            mem_parts = str(stats.get("MemUsage", "")).split("/")
            if len(mem_parts) == 2:
                mem_bytes, mem_limit = _parse_size(mem_parts[0]), _parse_size(mem_parts[1])
            if name in net_by_name:
                net_rx, net_tx = net_by_name[name]
            else:
                net_parts = str(stats.get("NetIO", "")).split("/")
                if len(net_parts) == 2:
                    net_rx, net_tx = _parse_size(net_parts[0]), _parse_size(net_parts[1])
        containers.append(
            {
                "name": name,
                "image": str(row.get("Image", "")),
                "state": str(row.get("State", "")),
                "status": status,
                "health": _container_health(status),
                "ports": str(row.get("Ports", "")),
                "cpu_percent": cpu_percent,
                "mem_bytes": mem_bytes,
                "mem_limit_bytes": mem_limit,
                "net_rx_bytes": net_rx,
                "net_tx_bytes": net_tx,
            }
        )
    containers.sort(key=lambda c: c["name"])
    return "ok", containers


async def gather_monitoring_sample(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> MonitoringSample:
    """Connect to a machine and take one monitoring sample — plus, only
    when `machine.is_physical`, hardware sensors/fans/S.M.A.R.T./power/GPUs
    (see _HARDWARE_COMMAND). Requires a pinned host key."""
    is_physical = bool(machine.is_physical)
    command = f"{MONITORING_COMMAND}; {_HARDWARE_COMMAND}" if is_physical else MONITORING_COMMAND
    async with machine_connection(machine, secret, timeout_seconds) as conn:
        # `docker stats --no-stream` alone takes a couple of seconds (it
        # waits for two cgroup readings), on top of the CPU probe's own
        # `sleep 1` — give the command itself more room than a bare connect.
        result = await conn.run(with_root_shim(command), check=False, timeout=timeout_seconds + 15)

    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_monitoring_output(raw, is_physical=is_physical)
