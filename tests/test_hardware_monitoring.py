"""Hardware monitoring across GPU vendors and CPUs (0.151.0): Intel Arc /
iGPU counters, NVIDIA temperature and PCI ids, the sysfs fallback when
lm-sensors is missing, hardware change detection and the whole-machine
power estimate."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.services import config_drift, power_estimate
from app.services.monitoring_history import build_monitoring_history
from app.ssh import monitoring
from app.ssh.monitoring import parse_monitoring_output
from app.ssh.onboarding import RAPL_GRANTS, SUDO_COMMANDS


def _base(extra: str = "") -> str:
    return (
        "===CPU===\n12.0\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n0\n" + extra
    )


# --- GPUs -----------------------------------------------------------------


def test_intel_arc_power_and_load_from_counters_and_vram_from_debugfs() -> None:
    lspci = '03:00.0 "VGA compatible controller" "Intel Corporation" "DG2 [Arc A380]"'
    raw = _base(
        "===GPUS===\n"
        f"drm\tcard1\t0x8086\t\t\t\t\t{lspci}\t0000:03:00.0\t0x56a5\t\t"
        "chunk_size: 4KiB, total: 6064MiB, free: 5040MiB, clear_free: 0MiB\n"
        "===GPU_COUNTERS===\n"
        "T 1000.00\ncard1 5000000 400000\n@@\nT 1002.00\ncard1 21000000 401500\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    (gpu,) = sample["gpus"]
    assert gpu["id"] == "8086:56a5@0000:03:00.0"
    assert gpu["name"] == "Intel Arc A380"
    assert gpu["power_watts"] == 8.0  # 16 J over 2 s
    assert gpu["util_percent"] == 25.0  # idle 1.5 s of 2 s
    assert gpu["vram_total_bytes"] == 6064 * 1024**2
    assert gpu["vram_used_bytes"] == 1024 * 1024**2
    assert gpu["pci_slot"] == "0000:03:00.0"
    assert sample["gpu_power_watts"] == 8.0


def test_intel_igpu_power_comes_from_rapl_uncore() -> None:
    raw = _base(
        "===GPUS===\n"
        "drm\tcard0\t0x8086\t\t\t\t\tIntel UHD 630\t0000:00:02.0\t0x3e92\t\t\n"
        "===GPU_COUNTERS===\n"
        "T 50.0\ncard0  9000\nuncore 1000000\n@@\nT 51.0\ncard0  9100\nuncore 3500000\n"
    )

    (gpu,) = parse_monitoring_output(raw, is_physical=True)["gpus"]

    assert gpu["power_watts"] == 2.5
    assert gpu["util_percent"] == 90.0


def test_counter_that_went_backwards_gives_no_reading() -> None:
    counters = monitoring._parse_gpu_counters(
        "T 10.0\ncard1 9000000 5000\n@@\nT 11.0\ncard1 10 4000\n"
    )
    assert counters == {}


def test_card_swap_starts_a_new_series_even_on_the_same_card_number() -> None:
    old = monitoring._parse_gpus(
        "drm\tcard0\t0x1002\t4\t1\t2\t3000000\tRadeon\t0000:03:00.0\t0x699f\t\t\n"
    )
    new = monitoring._parse_gpus(
        "drm\tcard0\t0x8086\t\t\t\t\tArc\t0000:03:00.0\t0x56a5\t\t"
        "total: 100MiB, free: 50MiB\n"
    )
    assert old[0]["id"] != new[0]["id"]


def test_nvidia_pci_id_and_temperature_joins_temperature_chart() -> None:
    raw = _base(
        "===GPUS===\n"
        "nvidia\t0\t\t37\t512\t12288\t45.20\tNVIDIA GeForce RTX 3060\t"
        "00000000:01:00.0\t0x250410DE\t61\t\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    (gpu,) = sample["gpus"]
    assert gpu["id"] == "10de:2504@0000:01:00.0"
    assert "temp_celsius" not in gpu
    assert {"name": "GPU NVIDIA GeForce RTX 3060", "celsius": 61.0} in sample["sensor_temps"]


def test_power_limit_is_not_read_as_gpu_draw() -> None:
    sensors = '{"i915-pci-0300": {"power1": {"power1_max": 55.0, "power1_crit": 400.0}}}'
    sample = parse_monitoring_output(_base(f"===SENSORS===\n{sensors}\n"), is_physical=True)
    assert sample["gpu_power_watts"] is None


# --- Sensors without lm-sensors ---------------------------------------------


def test_sysfs_fallback_reads_cpu_gpu_and_drive_sensors() -> None:
    raw = _base(
        "===SENSORS===\n@@SYSFS\n"
        "k10temp\t0000:00:18.3\ttemp1_input\tTctl\t48250\n"
        "coretemp\tcoretemp.0\ttemp1_input\tPackage id 0\t51000\n"
        "nvme\tnvme0\ttemp1_input\tComposite\t38850\n"
        "amdgpu\t0000:03:00.0\ttemp2_input\tjunction\t44000\n"
        "amdgpu\t0000:03:00.0\tpower1_average\tPPT\t12500000\n"
        "i915\t0000:04:00.0\tfan1_input\t\t1200\n"
        "acpitz\t\ttemp1_input\t\t-273200\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    temps = {t["name"]: t["celsius"] for t in sample["sensor_temps"]}
    assert temps == {
        "k10temp Tctl": 48.25,
        "coretemp Package id 0": 51.0,
        "nvme Composite": 38.85,
        "amdgpu junction": 44.0,
    }
    assert sample["sensor_fans"] == [{"name": "i915 fan1", "rpm": 1200.0}]
    assert sample["gpu_power_watts"] == 12.5


def test_hardware_command_is_valid_posix_shell() -> None:
    import shutil
    import subprocess

    shell = shutil.which("dash") or shutil.which("sh")
    assert shell
    script = (
        f"{monitoring._GPU_COUNTERS_PRELUDE}; {monitoring.MONITORING_COMMAND}; "
        f"{monitoring._HARDWARE_COMMAND}"
    )
    assert subprocess.run([shell, "-n", "-c", script], check=False).returncode == 0  # noqa: S603


def test_rapl_grants_are_exact_paths() -> None:
    assert set(RAPL_GRANTS) <= set(SUDO_COMMANDS)
    for grant in RAPL_GRANTS:
        assert "*" not in grant
        assert grant.endswith("/energy_uj")
        assert "\\:" in grant


# --- Hardware change detection ---------------------------------------------


def _machine(**fields: Any) -> Machine:
    machine = Machine(
        id=uuid.uuid4(), name="pc", ip_address="10.0.0.9", port=22, username="root",
        auth_method=AuthMethod.PASSWORD,
    )
    for key, value in fields.items():
        setattr(machine, key, value)
    return machine


_AMD = {
    "slot": "0000:03:00.0", "class_id": "0300", "vendor": "AMD", "device": "Radeon RX 550",
    "vendor_id": "1002", "device_id": "699f",
}
_ARC = {
    "slot": "0000:03:00.0", "class_id": "0300", "vendor": "Intel Corporation",
    "device": "DG2 [Arc A380]", "vendor_id": "8086", "device_id": "56a5",
}
_NIC = {"slot": "0000:05:00.0", "class_id": "0200", "vendor": "Intel", "device": "I226-V"}


def test_graphics_card_swap_is_a_change() -> None:
    before = config_drift.snapshot(_machine(pci_devices=[_AMD, _NIC]))
    after = config_drift.snapshot(_machine(pci_devices=[_ARC, _NIC]))

    (change,) = config_drift.diff_snapshots(before, after)

    assert change.field == "graphics"
    assert "Arc A380" in str(change.new_value)
    assert "Radeon RX 550" in str(change.old_value)


def test_drive_swapped_for_same_size_is_a_change_and_cpu_too() -> None:
    before = config_drift.snapshot(
        _machine(
            cpu_model="Intel Core i5-8500",
            smart_devices=[{"model": "Samsung SSD 870", "serial": "A1"}],
            ram_speed_mhz=2666,
        )
    )
    after = config_drift.snapshot(
        _machine(
            cpu_model="Intel Core i7-8700",
            smart_devices=[{"model": "Samsung SSD 870", "serial": "B2"}],
            ram_speed_mhz=3200,
        )
    )

    fields = {c.field for c in config_drift.diff_snapshots(before, after)}

    assert fields == {"cpu_model", "drives", "ram_speed"}


def test_unreadable_drives_or_pci_are_not_a_removal() -> None:
    before = config_drift.snapshot(
        _machine(smart_devices=[{"model": "WD Red", "serial": "X"}], pci_devices=[_AMD])
    )
    after = config_drift.snapshot(_machine(smart_devices=[], pci_devices=None))
    assert config_drift.diff_snapshots(before, after) == []


# --- GPU history and the power estimate ------------------------------------


def _sample(minutes_ago: int, **fields: Any) -> MachineMonitoringSample:
    values: dict[str, Any] = {
        "cpu_percent": 20.0, "network_io": [], "disk_io": [], "filesystems": [],
        "sensor_temps": [], "sensor_fans": [], "smart_disks": [], "gpus": [],
    }
    values.update(fields)
    return MachineMonitoringSample(
        id=uuid.uuid4(),
        machine_id=uuid.uuid4(),
        sampled_at=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        **values,
    )


def _gpu(gpu_id: str, power: float, slot: str = "0000:03:00.0") -> dict[str, Any]:
    return {
        "id": gpu_id, "name": gpu_id, "vendor": "amd", "power_watts": power,
        "util_percent": 1.0, "vram_used_bytes": None, "vram_total_bytes": None,
        "pci_slot": slot,
    }


def test_removed_gpu_is_marked_not_present() -> None:
    samples = [
        _sample(4, gpus=[_gpu("old", 3.5)]),
        _sample(2, gpus=[_gpu("new", 9.0)]),
    ]
    history = build_monitoring_history(samples, "1h")
    assert history.gpus["old"]["present"] is False
    assert history.gpus["new"]["present"] is True


def test_power_estimate_adds_components_and_psu_loss() -> None:
    samples = [
        _sample(4, cpu_energy_uj=0, gpus=[_gpu("g", 10.0)],
                sensor_fans=[{"name": "nct6798 fan2", "rpm": 900.0},
                             {"name": "amdgpu fan1", "rpm": 1500.0}]),
        _sample(2, cpu_energy_uj=2_400_000_000, gpus=[_gpu("g", 10.0)],
                sensor_fans=[{"name": "nct6798 fan2", "rpm": 900.0},
                             {"name": "amdgpu fan1", "rpm": 1500.0}]),
    ]
    history = build_monitoring_history(samples, "1h")
    machine = _machine(
        is_physical=True,
        ram_bytes=16 * 1024**3,
        smart_devices=[{"type": "nvme"}, {"type": "sata", "rotation_rpm": 7200}],
        network_links=[{"kind": "physical", "state": "up"}, {"kind": "virtual", "state": "up"}],
        pci_devices=[_AMD],
        ipmi={"sensors": [{"name": "Pwr Consumption", "value": 84.0, "unit": "W"}]},
    )

    estimate = power_estimate.estimate(history, machine)

    assert estimate.latest == {
        "cpu": 20.0, "gpu": 10.0, "ram": 6.0, "drives": 9.0, "fans": 1.5,
        "network": 1.0, "board": 15.0, "psu_loss": round(62.5 / 0.88 - 62.5, 1),
    }
    assert estimate.latest_total == round(62.5 / 0.88, 1)
    assert estimate.cpu_estimated is False
    assert estimate.measured_watts == 84.0


def test_power_estimate_without_rapl_guesses_cpu_and_counts_unmeasured_card() -> None:
    history = build_monitoring_history([_sample(2, cpu_percent=50.0)], "1h")
    machine = _machine(is_physical=True, cpu_cores=4, pci_devices=[_ARC])

    estimate = power_estimate.estimate(history, machine)

    assert estimate.cpu_estimated is True
    assert estimate.latest["cpu"] == 13.0  # 5 W + 50 % of 4 cores x 4 W
    assert estimate.latest["gpu"] == power_estimate.UNMEASURED_GPU_WATTS


def test_power_estimate_empty_for_a_vm() -> None:
    history = build_monitoring_history([_sample(2)], "1h")
    assert power_estimate.estimate(history, _machine(is_physical=False)).total == []
