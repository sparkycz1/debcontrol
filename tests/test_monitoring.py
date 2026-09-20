from __future__ import annotations

from app.ssh.monitoring import parse_monitoring_output


def test_parse_monitoring_output_full():
    raw = (
        "===CPU===\n"
        "23.1\n"
        "===LOAD===\n"
        "0.52 0.58 0.59\n"
        "===RAM_KB===\n"
        "16332828 6456285\n"
        "===NET===\n"
        "eth0 987654321 123456789\n"
        "===DISKIO===\n"
        "sda 102400000 76800000\n"
        "===FILESYSTEMS===\n"
        "/ 107374182400 32212254720 75161927680 30%\n"
        "===FAILED_SERVICES===\n"
        "2\n"
    )

    sample = parse_monitoring_output(raw)

    assert sample["cpu_percent"] == 23.1
    assert (sample["load1"], sample["load5"], sample["load15"]) == (0.52, 0.58, 0.59)
    assert sample["ram_total_bytes"] == 16332828 * 1024
    assert sample["ram_used_bytes"] == 6456285 * 1024
    assert sample["network_io"] == [
        {"iface": "eth0", "rx_bytes": 987654321, "tx_bytes": 123456789}
    ]
    assert sample["disk_io"] == [
        {"device": "sda", "read_bytes": 102400000, "write_bytes": 76800000}
    ]
    assert sample["filesystems"] == [
        {
            "mount": "/",
            "size_bytes": 107374182400,
            "used_bytes": 32212254720,
            "avail_bytes": 75161927680,
            "use_percent": 30,
        }
    ]
    assert sample["failed_services_count"] == 2
    # No hardware fields without `is_physical=True` — even though the
    # default here is a VM.
    assert sample["sensor_temps"] == []
    assert sample["sensor_fans"] == []
    assert sample["smart_disks"] == []
    assert sample["cpu_energy_uj"] is None
    assert sample["gpu_power_watts"] is None


def test_parse_monitoring_output_hardware_full():
    sensors_json = (
        '{"coretemp-isa-0000": {"Adapter": "ISA adapter", '
        '"Package id 0": {"temp1_input": 45.0, "temp1_max": 100.0}, '
        '"Core 0": {"temp2_input": 43.0}}, '
        '"nct6779-isa-0a20": {"Adapter": "ISA adapter", '
        '"fan1": {"fan1_input": 1200.0}, "fan2": {"fan2_input": 0.0}}}'
    )
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n3\n"
        "===SENSORS===\n"
        f"{sensors_json}\n"
        "===SMART===\n"
        "sda PASSED\n"
        "nvme0n1 FAILED\n"
        "===CPU_ENERGY_UJ===\n"
        "package-0 123456789\n"
        "===GPU_POWER===\n"
        "NVIDIA GeForce RTX 3060, 45.20\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    # A trailing hardware round trip glued onto FAILED_SERVICES's own
    # section must not break its own (unrelated) parsing.
    assert sample["failed_services_count"] == 3
    assert {"name": "Package id 0", "celsius": 45.0} in sample["sensor_temps"]
    assert {"name": "Core 0", "celsius": 43.0} in sample["sensor_temps"]
    assert {"name": "fan1", "rpm": 1200.0} in sample["sensor_fans"]
    assert {"name": "fan2", "rpm": 0.0} in sample["sensor_fans"]
    assert sample["smart_disks"] == [
        {"device": "sda", "healthy": True},
        {"device": "nvme0n1", "healthy": False},
    ]
    assert sample["cpu_energy_uj"] == 123456789
    assert sample["gpu_power_watts"] == 45.20


def test_parse_monitoring_output_hardware_gracefully_empty_on_a_vm():
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n"
        "===SENSORS===\n===SMART===\n===CPU_ENERGY_UJ===\n===GPU_POWER===\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    assert sample["sensor_temps"] == []
    assert sample["sensor_fans"] == []
    assert sample["smart_disks"] == []
    assert sample["cpu_energy_uj"] is None
    assert sample["gpu_power_watts"] is None


def test_parse_monitoring_output_sensors_malformed_json_is_ignored():
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n"
        "===SENSORS===\nnot json at all\n===SMART===\n===CPU_ENERGY_UJ===\n===GPU_POWER===\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    assert sample["sensor_temps"] == []
    assert sample["sensor_fans"] == []


def test_parse_monitoring_output_amd_gpu_power_from_sensors_when_no_nvidia():
    # amdgpu's own hwmon power reading, surfaced through `sensors -j` —
    # no nvidia-smi output at all (an AMD-only machine).
    sensors_json = (
        '{"amdgpu-pci-0300": {"Adapter": "PCI adapter", '
        '"edge": {"temp1_input": 50.0}, "PPT": {"power1_average": 65.3}}}'
    )
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n"
        f"===SENSORS===\n{sensors_json}\n"
        "===SMART===\n===CPU_ENERGY_UJ===\n===GPU_POWER===\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    assert sample["gpu_power_watts"] == 65.3


def test_parse_monitoring_output_nvidia_gpu_power_preferred_over_sensors():
    sensors_json = '{"amdgpu-pci-0300": {"PPT": {"power1_average": 65.3}}}'
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n"
        f"===SENSORS===\n{sensors_json}\n"
        "===SMART===\n===CPU_ENERGY_UJ===\n"
        "===GPU_POWER===\nNVIDIA GeForce RTX 3060, 45.20\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    assert sample["gpu_power_watts"] == 45.20


def test_parse_monitoring_output_cpu_chip_power_reading_not_mistaken_for_gpu():
    # k10temp (AMD CPU temp sensor) has no power reading in practice, but
    # even if some other non-GPU chip exposed a "power*" key, it must not
    # be picked up as gpu_power_watts — only amdgpu/i915/xe chips count.
    sensors_json = '{"k10temp-pci-00c3": {"Tctl": {"temp1_input": 40.0}}}'
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n"
        f"===SENSORS===\n{sensors_json}\n"
        "===SMART===\n===CPU_ENERGY_UJ===\n===GPU_POWER===\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    assert sample["gpu_power_watts"] is None


def test_parse_monitoring_output_smart_unrecognized_status_is_none():
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n"
        "===SENSORS===\n===SMART===\nsda UNKNOWN\n===CPU_ENERGY_UJ===\n===GPU_POWER===\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    assert sample["smart_disks"] == [{"device": "sda", "healthy": None}]


def test_parse_monitoring_output_multiple_interfaces_and_disks():
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n"
        "===NET===\n"
        "eth0 100 200\n"
        "wg0 300 400\n"
        "===DISKIO===\n"
        "sda 1000 2000\n"
        "nvme0n1 3000 4000\n"
        "===FILESYSTEMS===\n"
        "===FAILED_SERVICES===\n"
    )

    sample = parse_monitoring_output(raw)

    assert [n["iface"] for n in sample["network_io"]] == ["eth0", "wg0"]
    assert [d["device"] for d in sample["disk_io"]] == ["sda", "nvme0n1"]


def test_parse_monitoring_output_multiple_filesystems():
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n"
        "/ 1000 500 500 50%\n"
        "/boot 2000 100 1900 5%\n"
        "===FAILED_SERVICES===\n"
    )

    sample = parse_monitoring_output(raw)

    assert [fs["mount"] for fs in sample["filesystems"]] == ["/", "/boot"]
    assert sample["filesystems"][0]["use_percent"] == 50
    assert sample["filesystems"][1]["use_percent"] == 5


def test_parse_monitoring_output_handles_missing_sections():
    sample = parse_monitoring_output("===CPU===\n===LOAD===\n===RAM_KB===\n")

    assert sample["cpu_percent"] is None
    assert sample["load1"] is None
    assert sample["ram_used_bytes"] is None
    assert sample["network_io"] == []
    assert sample["disk_io"] == []
    assert sample["filesystems"] == []
    assert sample["failed_services_count"] is None


def test_parse_monitoring_output_empty_string():
    sample = parse_monitoring_output("")

    assert sample["cpu_percent"] is None
    assert sample["load1"] is None
    assert sample["network_io"] == []
    assert sample["disk_io"] == []
    assert sample["filesystems"] == []
    assert sample["failed_services_count"] is None


def test_parse_monitoring_output_zero_failed_services_is_not_none():
    # "0" must parse as the integer 0 (genuinely no failed services), not
    # be confused with "couldn't tell" (None).
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n0\n"
    )

    sample = parse_monitoring_output(raw)

    assert sample["failed_services_count"] == 0
