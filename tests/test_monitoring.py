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
        "===GPUS===\n"
        "nvidia\t0\t\t37\t512\t12288\t45.20\tNVIDIA GeForce RTX 3060\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    # A trailing hardware round trip glued onto FAILED_SERVICES's own
    # section must not break its own (unrelated) parsing.
    assert sample["failed_services_count"] == 3
    assert {"name": "coretemp Package id 0", "celsius": 45.0} in sample["sensor_temps"]
    assert {"name": "coretemp Core 0", "celsius": 43.0} in sample["sensor_temps"]
    assert {"name": "nct6779 fan1", "rpm": 1200.0} in sample["sensor_fans"]
    assert {"name": "nct6779 fan2", "rpm": 0.0} in sample["sensor_fans"]
    assert sample["smart_disks"] == [
        {"device": "sda", "healthy": True},
        {"device": "nvme0n1", "healthy": False},
    ]
    assert sample["cpu_energy_uj"] == 123456789
    assert sample["gpu_power_watts"] == 45.20
    assert sample["gpus"] == [
        {
            "id": "nvidia0",
            "vendor": "nvidia",
            "name": "NVIDIA GeForce RTX 3060",
            "util_percent": 37.0,
            "vram_used_bytes": 512 * 1048576,
            "vram_total_bytes": 12288 * 1048576,
            "power_watts": 45.2,
        }
    ]


def test_parse_monitoring_output_hardware_gracefully_empty_on_a_vm():
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n"
        "===SENSORS===\n===SMART===\n===CPU_ENERGY_UJ===\n===GPUS===\n"
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
        "===SENSORS===\nnot json at all\n===SMART===\n===CPU_ENERGY_UJ===\n===GPUS===\n"
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
        "===SMART===\n===CPU_ENERGY_UJ===\n===GPUS===\n"
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
        "===GPUS===\nnvidia\t0\t\t37\t512\t12288\t45.20\tNVIDIA GeForce RTX 3060\n"
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
        "===SMART===\n===CPU_ENERGY_UJ===\n===GPUS===\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    assert sample["gpu_power_watts"] is None


def test_parse_monitoring_output_smart_unrecognized_status_is_none():
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n"
        "===SENSORS===\n===SMART===\nsda UNKNOWN\n===CPU_ENERGY_UJ===\n===GPUS===\n"
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


def _base(extra: str = "") -> str:
    return (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n0\n" + extra
    )


def test_parse_monitoring_output_sections_are_matched_by_name_not_position():
    # FILESYSTEMS missing entirely and DOCKER before hardware output —
    # nothing shifts into the wrong section.
    raw = (
        "===CPU===\n12.5\n===LOAD===\n0.1 0.2 0.3\n===RAM_KB===\n100 50\n"
        "===NET===\n===DISKIO===\n===FAILED_SERVICES===\n4\n===DOCKER===\n"
        "===CPU_ENERGY_UJ===\npackage-0 10\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    assert sample["cpu_percent"] == 12.5
    assert sample["failed_services_count"] == 4
    assert sample["filesystems"] == []
    assert sample["cpu_energy_uj"] == 10


def test_parse_monitoring_output_amd_gpu_from_drm_sysfs():
    lspci = (
        '03:00.0 "VGA compatible controller" "Advanced Micro Devices, Inc. [AMD/ATI]" '
        '"Lexa PRO [Radeon 540/540X/550/550X / RX 540X/550/550X]" -rc7 "Micro-Star" '
        '"Radeon RX 550"'
    )
    raw = _base(
        "===SENSORS===\n===SMART===\n===CPU_ENERGY_UJ===\n===GPUS===\n"
        f"drm\tcard0\t0x1002\t4\t268435456\t4294967296\t3200000\t{lspci}\n"
        "drm\tcard1\t0x1234\t\t\t\t\tQEMU\n"
    )

    sample = parse_monitoring_output(raw, is_physical=True)

    (gpu,) = sample["gpus"]
    assert gpu["vendor"] == "amd"
    assert gpu["name"] == "AMD Radeon 540/540X/550/550X / RX 540X/550/550X"
    assert gpu["util_percent"] == 4.0
    assert gpu["vram_used_bytes"] == 268435456
    assert gpu["vram_total_bytes"] == 4294967296
    assert gpu["power_watts"] == 3.2
    assert sample["gpu_power_watts"] == 3.2


def test_parse_monitoring_output_gpu_with_no_metrics_is_skipped():
    raw = _base("===GPUS===\ndrm\tcard0\t0x8086\t\t\t\t\tIntel UHD\n")

    sample = parse_monitoring_output(raw, is_physical=True)

    assert sample["gpus"] == []


def test_parse_monitoring_output_cpu_energy_sums_packages_only():
    raw = _base("===CPU_ENERGY_UJ===\npackage-0 100\ncore 40\npackage-1 200\n")

    sample = parse_monitoring_output(raw, is_physical=True)

    assert sample["cpu_energy_uj"] == 300


def test_parse_monitoring_output_sensor_names_are_unique_across_chips():
    sensors_json = (
        '{"nvme-pci-0100": {"Composite": {"temp1_input": 40.0}}, '
        '"nvme-pci-0200": {"Composite": {"temp1_input": 36.0}}}'
    )
    raw = _base(f"===SENSORS===\n{sensors_json}\n")

    sample = parse_monitoring_output(raw, is_physical=True)

    assert [t["name"] for t in sample["sensor_temps"]] == [
        "nvme Composite",
        "nvme Composite (2)",
    ]


def test_parse_monitoring_output_no_docker_cli():
    sample = parse_monitoring_output(_base())

    assert sample["docker_status"] is None
    assert sample["docker_containers"] == []


def test_parse_monitoring_output_docker_no_access():
    sample = parse_monitoring_output(_base("===DOCKER===\n@@NOACCESS\n"))

    assert sample["docker_status"] == "no_access"
    assert sample["docker_containers"] == []


def test_parse_monitoring_output_docker_containers():
    ps_server = (
        '{"Names":"immich_server","Image":"ghcr.io/immich-app/immich-server:release",'
        '"State":"running","Status":"Up 10 days (healthy)","Ports":"0.0.0.0:2283->2283/tcp"}'
    )
    ps_old = (
        '{"Names":"old","Image":"busybox","State":"exited","Status":"Exited (0) 3 days ago",'
        '"Ports":""}'
    )
    stats_server = (
        '{"Name":"immich_server","CPUPerc":"0.03%","MemUsage":"753.1MiB / 15.5GiB",'
        '"NetIO":"5.4kB / 1kB"}'
    )
    raw = _base(
        "===DOCKER===\n@@PS\n"
        f"{ps_server}\n{ps_old}\n"
        f"@@STATS\n{stats_server}\n"
        "@@NET\nimmich_server 123456 7890\n"
    )

    sample = parse_monitoring_output(raw)

    assert sample["docker_status"] == "ok"
    server, old = sample["docker_containers"]
    assert server["name"] == "immich_server"
    assert old["name"] == "old"
    assert server["health"] == "healthy"
    assert server["cpu_percent"] == 0.03
    assert server["mem_bytes"] == int(753.1 * 1024**2)
    # Exact namespace counters win over docker stats' rounded NetIO.
    assert (server["net_rx_bytes"], server["net_tx_bytes"]) == (123456, 7890)
    assert old["cpu_percent"] is None
    assert old["health"] is None


def test_parse_monitoring_output_docker_netio_fallback():
    raw = _base(
        "===DOCKER===\n@@PS\n"
        '{"Names":"web","Image":"nginx","State":"running","Status":"Up 1 hour","Ports":""}\n'
        "@@STATS\n"
        '{"Name":"web","CPUPerc":"1.50%","MemUsage":"10MiB / 1GiB","NetIO":"66kB / 4.1kB"}\n'
        "@@NET\n"
    )

    (web,) = parse_monitoring_output(raw)["docker_containers"]

    assert web["net_rx_bytes"] == 66_000
    assert web["net_tx_bytes"] == 4_100
