from __future__ import annotations

from app.ssh.facts import FACTS_COMMAND, parse_facts_output


def test_parse_facts_output_full_no_reboot_needed():
    raw = (
        "===HOSTNAME===\n"
        "web1\n"
        "===OS===\n"
        "Debian GNU/Linux 12 (bookworm)\n"
        "===OS_ID===\n"
        "debian\n"
        "===KERNEL===\n"
        "6.1.0-13-amd64\n"
        "===KERNEL_LATEST===\n"
        "6.1.0-13-amd64\n"
        "===ARCH===\n"
        "x86_64\n"
        "===CPU===\n"
        "4\n"
        "===CPU_MODEL===\n"
        "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
        "===RAM_KB===\n"
        "8058000\n"
        "===RAM_SPEED===\n"
        "2400\n"
        "===DISKS===\n"
        "sda 500107862016\n"
        "vda 21474836480\n"
        "===UPTIME===\n"
        "123456\n"
        "===PROCESSES===\n"
        "187\n"
        "===FILESYSTEMS===\n"
        "/ 21474836480 10737418240 9663676416 51%\n"
        "/boot 536870912 107374182 407896228 21%\n"
        "===NETWORK===\n"
        "eth0 192.168.1.10/24\n"
        "wg0 10.0.0.5/32\n"
    )

    facts = parse_facts_output(raw)

    assert facts["hostname"] == "web1"
    assert facts["os_version"] == "Debian GNU/Linux 12 (bookworm)"
    assert facts["os_id"] == "debian"
    assert facts["kernel_version"] == "6.1.0-13-amd64"
    assert facts["cpu_architecture"] == "x86_64"
    assert facts["cpu_cores"] == 4
    assert facts["cpu_model"] == "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"
    assert facts["ram_bytes"] == 8058000 * 1024
    assert facts["ram_speed_mhz"] == 2400
    assert facts["disks"] == [
        {"name": "sda", "size_bytes": 500107862016},
        {"name": "vda", "size_bytes": 21474836480},
    ]
    # Running kernel matches the latest installed kernel package.
    assert facts["reboot_required"] is False
    assert facts["uptime_seconds"] == 123456
    assert facts["process_count"] == 187
    assert facts["filesystems"] == [
        {
            "mount": "/",
            "size_bytes": 21474836480,
            "used_bytes": 10737418240,
            "avail_bytes": 9663676416,
            "use_percent": 51,
        },
        {
            "mount": "/boot",
            "size_bytes": 536870912,
            "used_bytes": 107374182,
            "avail_bytes": 407896228,
            "use_percent": 21,
        },
    ]
    assert facts["network_interfaces"] == [
        {"interface": "eth0", "address": "192.168.1.10/24"},
        {"interface": "wg0", "address": "10.0.0.5/32"},
    ]


def test_parse_facts_output_reboot_required_when_kernel_differs():
    raw = (
        "===HOSTNAME===\nweb1\n"
        "===OS===\nDebian GNU/Linux 12 (bookworm)\n"
        "===OS_ID===\ndebian\n"
        "===KERNEL===\n6.1.0-13-amd64\n"
        "===KERNEL_LATEST===\n6.1.0-18-amd64\n"
        "===ARCH===\nx86_64\n"
        "===CPU===\n4\n"
        "===CPU_MODEL===\n"
        "===RAM_KB===\n8058000\n"
        "===RAM_SPEED===\n"
        "===DISKS===\n"
        "===UPTIME===\n999\n"
        "===PROCESSES===\n120\n"
        "===FILESYSTEMS===\n"
        "===NETWORK===\n"
    )

    facts = parse_facts_output(raw)

    assert facts["kernel_version"] == "6.1.0-13-amd64"
    assert facts["reboot_required"] is True


def test_parse_facts_output_reboot_unknown_without_kernel_latest():
    # E.g. no dpkg / no linux-image-* packages found (some minimal images).
    # Every `echo ===X===` marker always runs even when the command after it
    # produces nothing, so a real transcript never skips a section outright.
    raw = (
        "===HOSTNAME===\nweb1\n===OS===\n===OS_ID===\n===KERNEL===\n6.1.0-13-amd64\n"
        "===KERNEL_LATEST===\n===ARCH===\naarch64\n===CPU===\n===CPU_MODEL===\n"
        "===RAM_KB===\n===RAM_SPEED===\n"
        "===DISKS===\n===UPTIME===\n===PROCESSES===\n===FILESYSTEMS===\n===NETWORK===\n"
    )

    facts = parse_facts_output(raw)

    assert facts["kernel_version"] == "6.1.0-13-amd64"
    assert facts["reboot_required"] is None
    assert facts["cpu_architecture"] == "aarch64"
    assert facts["uptime_seconds"] is None
    assert facts["process_count"] is None
    assert facts["filesystems"] == []
    assert facts["network_interfaces"] == []


def test_parse_facts_output_handles_missing_sections():
    # E.g. a connection that drops mid-way, or commands that aren't present.
    raw = "===HOSTNAME===\nweb1\n===OS===\n===OS_ID===\n"

    facts = parse_facts_output(raw)

    assert facts["hostname"] == "web1"
    assert facts["os_version"] is None
    assert facts["kernel_version"] is None
    assert facts["cpu_architecture"] is None
    assert facts["cpu_cores"] is None
    assert facts["ram_bytes"] is None
    assert facts["disks"] == []
    assert facts["reboot_required"] is None
    assert facts["uptime_seconds"] is None
    assert facts["process_count"] is None
    assert facts["filesystems"] == []
    assert facts["network_interfaces"] == []


def test_parse_facts_output_empty_string():
    facts = parse_facts_output("")

    assert facts["hostname"] is None
    assert facts["disks"] == []
    assert facts["reboot_required"] is None
    assert facts["cpu_architecture"] is None
    assert facts["uptime_seconds"] is None
    assert facts["process_count"] is None
    assert facts["filesystems"] == []
    assert facts["network_interfaces"] == []
    assert facts["is_physical"] is None


def _raw_up_to_network(virt_body: str) -> str:
    """`_split_sections` pairs chunks against `_SECTION_MARKERS`
    positionally, so a fixture testing a later section (VIRT, the last
    marker) needs every earlier marker present too, in order — dropping
    one from the *middle* (unlike dropping a trailing suffix, which
    `test_parse_facts_output_handles_missing_sections` above covers) would
    silently misalign every section after the gap."""
    return (
        "===HOSTNAME===\nweb1\n===OS===\n===OS_ID===\n===KERNEL===\n"
        "===KERNEL_LATEST===\n===ARCH===\n===CPU===\n===CPU_MODEL===\n"
        "===RAM_KB===\n===RAM_SPEED===\n===DISKS===\n===UPTIME===\n"
        "===PROCESSES===\n===FILESYSTEMS===\n===NETWORK===\n"
        f"===VIRT===\n{virt_body}"
    )


def test_parse_facts_output_virt_none_means_physical():
    facts = parse_facts_output(_raw_up_to_network("none\n"))
    assert facts["is_physical"] is True


def test_parse_facts_output_virt_kvm_means_not_physical():
    facts = parse_facts_output(_raw_up_to_network("kvm\n"))
    assert facts["is_physical"] is False


def test_parse_facts_output_virt_missing_binary_is_unknown():
    # command not found: VIRT section body is empty.
    facts = parse_facts_output(_raw_up_to_network(""))
    assert facts["is_physical"] is None


def test_parse_facts_output_filesystems_ignores_malformed_lines():
    raw = (
        "===HOSTNAME===\nweb1\n===OS===\n===OS_ID===\n===KERNEL===\n===KERNEL_LATEST===\n===ARCH===\n"
        "===CPU===\n===CPU_MODEL===\n===RAM_KB===\n===RAM_SPEED===\n"
        "===DISKS===\n===UPTIME===\n===PROCESSES===\n"
        "===FILESYSTEMS===\n"
        "not enough fields\n"
        "/ 100 50 50 50%\n"
        "===NETWORK===\n"
    )

    facts = parse_facts_output(raw)

    assert facts["filesystems"] == [
        {
            "mount": "/",
            "size_bytes": 100,
            "used_bytes": 50,
            "avail_bytes": 50,
            "use_percent": 50,
        }
    ]


# --- CPU_MODEL section of FACTS_COMMAND: the remote shell fragment itself
# — same "assert on the built command string" convention
# `test_build_update_command_*` (tests/test_updates.py) uses for its shell
# scripts, not a real shell execution (this repo's tests run on Windows
# dev machines too, where faking a PATH-shadowed `lscpu` for a real bash
# subprocess is its own can of worms). This guards against the exact
# regression that shipped the x86-only bug in the first place: someone
# reverting to a bare `/proc/cpuinfo` read with no `lscpu` preference.


def test_facts_command_prefers_lscpu_for_cpu_model():
    # `/proc/cpuinfo`'s `model name` field is x86-only — empty on ARM
    # (Raspberry Pi, an ARM cloud instance). `lscpu`'s own `Model name:`
    # line exists on both architectures, so it must be tried first.
    cpu_model_section = FACTS_COMMAND.split("===CPU_MODEL===")[1].split("===RAM_KB===")[0]
    assert "lscpu" in cpu_model_section
    assert cpu_model_section.index("lscpu") < cpu_model_section.index("/proc/cpuinfo")


def test_facts_command_cpu_model_tolerates_lscpus_indented_tree_output():
    # Modern util-linux nests "Model name:" under "Vendor ID:" with leading
    # whitespace in lscpu's tree-style output — a grep anchored to column 1
    # would silently never match it.
    cpu_model_section = FACTS_COMMAND.split("===CPU_MODEL===")[1].split("===RAM_KB===")[0]
    assert "^[[:space:]]*Model name:" in cpu_model_section


def test_facts_command_still_falls_back_to_proc_cpuinfo():
    cpu_model_section = FACTS_COMMAND.split("===CPU_MODEL===")[1].split("===RAM_KB===")[0]
    assert "|| " in cpu_model_section
    assert "model name' /proc/cpuinfo" in cpu_model_section
