"""The whole machine's estimated power draw — what it takes from the wall.

Only the CPU (RAPL) and most GPUs measure their own draw; everything else
on a board doesn't. So the Monitoring tab's "Estimated total power" adds
what *is* measured to typical figures for the rest, then the power
supply's own loss:

- **CPU** — RAPL's package power (`cpu_power_watts`). Without RAPL (an
  older kernel, no root grant, an ARM board) a rough guess from CPU load
  and core count instead, flagged as such.
- **GPUs** — each card's own reading (`gpus[...].power`), or the sensors
  fallback total. An Intel iGPU is left out: RAPL's package already
  includes it. A discrete card the machine has (`Machine.pci_devices`)
  but which reports no power counts as `UNMEASURED_GPU_WATTS`.
- **RAM** per GiB, **drives** by kind (NVMe, SATA SSD, spinning disk —
  `Machine.smart_devices`, else `Machine.disks`), **fans** that are
  spinning (a GPU's own fans are part of the GPU's reading), **network
  ports** with a link, and the **board** (chipset, VRM, BMC, USB...).
- **Power supply loss** — the sum over `PSU_EFFICIENCY`.

When the machine's BMC reports the real draw (an IPMI sensor in watts,
`Machine.ipmi`), that measured value is shown next to the estimate.

Pure functions over an already-built `MonitoringHistory` and the machine's
facts — no I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.services.monitoring_history import MonitoringHistory

# Typical figures, rounded — an estimate, not a measurement.
BOARD_WATTS = 15.0
RAM_WATTS_PER_GIB = 0.375  # ~3 W per 8 GiB DDR4/DDR5 module
DRIVE_WATTS = {"nvme": 3.0, "ssd": 1.5, "hdd": 6.0, "unknown": 3.0}
FAN_WATTS = 1.5
NIC_WATTS = 1.0
UNMEASURED_GPU_WATTS = 15.0
CPU_IDLE_WATTS = 5.0
CPU_WATTS_PER_CORE = 4.0
PSU_EFFICIENCY = 0.88

COMPONENTS = ("cpu", "gpu", "ram", "drives", "fans", "network", "board", "psu_loss")

# A fan on a GPU chip is powered by the card (already in its reading).
_GPU_FAN_PREFIXES = ("amdgpu", "i915", "xe ", "nvidia", "nouveau", "radeon")
# IPMI sensor names for the whole system's input power.
_IPMI_TOTAL_RE = re.compile(
    r"(consum|power meter|total power|sys(tem)? power|pwr meter|input power|^power$)", re.I
)
_IPMI_PSU_INPUT_RE = re.compile(r"(psu|ps)\s*\d*\s*(input|in)\b", re.I)


@dataclass
class PowerEstimate:
    # Per chart bucket (`MonitoringHistory.bucket_timestamps`), watts.
    cpu: list[float | None] = field(default_factory=list)
    gpu: list[float | None] = field(default_factory=list)
    # RAM, drives, fans, network ports and the board together.
    other: list[float | None] = field(default_factory=list)
    psu_loss: list[float | None] = field(default_factory=list)
    total: list[float | None] = field(default_factory=list)
    # The newest bucket with data, split into every component (watts).
    latest: dict[str, float] = field(default_factory=dict)
    latest_total: float | None = None
    # True when the CPU part is guessed from load (no RAPL).
    cpu_estimated: bool = False
    # Measured by the BMC (IPMI), when the machine has one that reports it.
    measured_watts: float | None = None


def _drive_kind(drive: dict[str, Any]) -> str:
    kind = str(drive.get("type") or "").lower()
    if kind == "nvme":
        return "nvme"
    rpm = drive.get("rotation_rpm")
    if isinstance(rpm, int | float) and rpm > 0:
        return "hdd"
    if kind in ("sata", "sas", "scsi", "ata"):
        return "ssd"
    return "unknown"


def drives_watts(machine: Any) -> float:
    smart = [d for d in (machine.smart_devices or []) if isinstance(d, dict)]
    if smart:
        return sum(DRIVE_WATTS[_drive_kind(d)] for d in smart)
    disks = [
        d
        for d in (machine.disks or [])
        if isinstance(d, dict) and not str(d.get("name") or "").startswith(("loop", "zram", "ram"))
    ]
    return sum(
        DRIVE_WATTS["nvme" if str(d.get("name") or "").startswith("nvme") else "unknown"]
        for d in disks
    )


def network_watts(machine: Any) -> float:
    links = [
        link
        for link in (machine.network_links or [])
        if isinstance(link, dict) and link.get("kind") in ("physical", "wireless")
    ]
    return NIC_WATTS * sum(1 for link in links if link.get("state") == "up")


def _is_integrated(vendor_id: str | None, slot: str | None) -> bool:
    return (vendor_id or "").lower().removeprefix("0x") == "8086" and str(slot or "").endswith(
        "00:02.0"
    )


def unmeasured_gpus(machine: Any, history: MonitoringHistory) -> int:
    """Discrete display cards the machine has whose power isn't read."""
    measured = {
        str(info.get("pci_slot"))
        for info in history.gpus.values()
        if info.get("present") and info.get("power") and info.get("pci_slot")
    }
    count = 0
    for device in machine.pci_devices or []:
        if not isinstance(device, dict) or not str(device.get("class_id") or "").startswith("03"):
            continue
        slot = str(device.get("slot") or "")
        if _is_integrated(device.get("vendor_id"), slot):
            continue
        if not any(m.endswith(slot) or slot.endswith(m) for m in measured):
            count += 1
    return count


def measured_ipmi_watts(ipmi: dict[str, Any] | None) -> float | None:
    """The system's input power from the BMC: a "Pwr Consumption"/"Power
    Meter"-like sensor, else the PSUs' input readings added up."""
    sensors = [
        s
        for s in (ipmi or {}).get("sensors") or []
        if isinstance(s, dict) and s.get("unit") == "W" and isinstance(s.get("value"), int | float)
    ]
    for sensor in sensors:
        if _IPMI_TOTAL_RE.search(str(sensor.get("name") or "")) and sensor["value"] > 0:
            return float(sensor["value"])
    inputs = [
        float(s["value"])
        for s in sensors
        if _IPMI_PSU_INPUT_RE.search(str(s.get("name") or "")) and s["value"] > 0
    ]
    return round(sum(inputs), 1) if inputs else None


def _discrete_gpu_series(history: MonitoringHistory, size: int) -> list[float | None]:
    series: list[list[float | None]] = [
        info["power"]
        for info in history.gpus.values()
        if info.get("power") and not _is_integrated(
            "8086" if info.get("vendor") == "intel" else None, info.get("pci_slot")
        )
    ]
    if not series:
        fallback = history.gpu_power_watts
        return list(fallback) if any(v is not None for v in fallback) else [None] * size
    total: list[float | None] = []
    for i in range(size):
        values: list[float] = [v for s in series if i < len(s) and (v := s[i]) is not None]
        total.append(sum(values) if values else None)
    return total


def _spinning_fans(history: MonitoringHistory, i: int) -> int:
    count = 0
    for name, values in history.fans_by_sensor.items():
        if name.lower().startswith(_GPU_FAN_PREFIXES):
            continue
        value = values[i] if i < len(values) else None
        if value is not None and value > 0:
            count += 1
    return count


def estimate(history: MonitoringHistory, machine: Any) -> PowerEstimate:
    """The estimate for every bucket of `history`; empty for a virtual
    machine (its power is its host's) or a window with no samples."""
    result = PowerEstimate(measured_watts=measured_ipmi_watts(machine.ipmi))
    if machine.is_physical is False or not history.bucket_timestamps:
        return result
    size = len(history.bucket_timestamps)
    gpu_series = _discrete_gpu_series(history, size)
    extra_gpus = unmeasured_gpus(machine, history) * UNMEASURED_GPU_WATTS
    ram = round((machine.ram_bytes or 0) / 1024**3 * RAM_WATTS_PER_GIB, 1)
    drives = drives_watts(machine)
    network = network_watts(machine)
    cores = machine.cpu_cores or 1
    has_rapl = any(v is not None for v in history.cpu_power_watts)
    result.cpu_estimated = not has_rapl

    for i in range(size):
        cpu_load = history.cpu_percent[i] if i < len(history.cpu_percent) else None
        cpu: float | None
        if has_rapl:
            cpu = history.cpu_power_watts[i] if i < len(history.cpu_power_watts) else None
        else:
            cpu = (
                None
                if cpu_load is None
                else CPU_IDLE_WATTS + cpu_load / 100 * cores * CPU_WATTS_PER_CORE
            )
        if cpu is None or cpu_load is None:
            for series in (result.cpu, result.gpu, result.other, result.psu_loss, result.total):
                series.append(None)
            continue
        gpu = (gpu_series[i] or 0.0) + extra_gpus
        fans = _spinning_fans(history, i) * FAN_WATTS
        other = ram + drives + fans + network + BOARD_WATTS
        dc = cpu + gpu + other
        loss = dc / PSU_EFFICIENCY - dc
        result.cpu.append(round(cpu, 1))
        result.gpu.append(round(gpu, 1))
        result.other.append(round(other, 1))
        result.psu_loss.append(round(loss, 1))
        result.total.append(round(dc + loss, 1))
        result.latest = {
            "cpu": round(cpu, 1),
            "gpu": round(gpu, 1),
            "ram": ram,
            "drives": round(drives, 1),
            "fans": round(fans, 1),
            "network": round(network, 1),
            "board": BOARD_WATTS,
            "psu_loss": round(loss, 1),
        }
        result.latest_total = round(dc + loss, 1)
    return result
