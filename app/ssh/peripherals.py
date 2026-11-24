"""What is plugged into a machine: PCIe and USB devices, and on a server
with a BMC its IPMI sensors and event log — the Monitoring tab's
"Devices" cards and `GET /api/v1/machines/{id}/hardware`.

Gathered as extra sections of `app.ssh.facts.FACTS_COMMAND` (hourly, the
facts cadence): none of it moves on a minutes scale, and an IPMI read
can take seconds on a slow BMC.

- **PCI** — `lspci -vmmnnkD` (pciutils) when installed: names, numeric
  ids, the kernel driver in use and, with pciutils 3.6+, the IOMMU group.
  Without pciutils, the same devices straight from sysfs (ids and driver,
  no names). The IOMMU groups always come from `/sys/kernel/iommu_groups`
  too — what PCI passthrough to a VM depends on. Nothing needs root.
- **USB** — straight from sysfs (`/sys/bus/usb/devices`): ids, the
  device's own manufacturer/product strings, speed and the drivers bound
  to its interfaces. `lsusb` is not needed; the Linux root hubs are left
  out.
- **IPMI** — bare metal only, and only when `ipmitool` and an IPMI device
  node exist: `ipmitool sdr list` (sensors) and `ipmitool sel elist last
  20` (the newest system event log entries). Needs root — the onboarding
  sudoers grant allows exactly those two command lines. Each is capped
  with `timeout`, so a BMC that hangs cannot stall the whole facts run.
"""

from __future__ import annotations

import re
from typing import Any

PCI_MARKER = "PCI"
USB_MARKER = "USB"
IPMI_MARKER = "IPMI"
MARKERS = (PCI_MARKER, USB_MARKER, IPMI_MARKER)

# Caps on what is kept per machine — a sane machine has far fewer.
MAX_PCI_DEVICES = 256
MAX_USB_DEVICES = 128
MAX_IPMI_SENSORS = 256
SEL_ENTRIES = 20

# The exact command lines the sudoers grant allows (app.ssh.onboarding).
IPMI_SDR_ARGS = "sdr list"
IPMI_SEL_ARGS = f"sel elist last {SEL_ENTRIES}"

PCI_SECTION = (
    f"echo ==={PCI_MARKER}===; "
    "if command -v lspci >/dev/null 2>&1; then echo @@LSPCI; lspci -vmmnnkD 2>/dev/null; "
    "else echo @@SYSFS; "
    "for d in /sys/bus/pci/devices/*; do [ -r \"$d/class\" ] || continue; "
    "drv=; [ -L \"$d/driver\" ] && drv=\"$(basename \"$(readlink \"$d/driver\")\")\"; "
    "printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"${d##*/}\" \"$(cat \"$d/class\" 2>/dev/null)\" "
    "\"$(cat \"$d/vendor\" 2>/dev/null)\" \"$(cat \"$d/device\" 2>/dev/null)\" \"$drv\"; "
    "done; fi; "
    "echo @@IOMMU; "
    "for g in /sys/kernel/iommu_groups/*/devices/*; do [ -e \"$g\" ] || continue; "
    "x=\"${g%/devices/*}\"; echo \"${g##*/} ${x##*/}\"; done"
)

USB_SECTION = (
    f"echo ==={USB_MARKER}===; "
    "for d in /sys/bus/usb/devices/*; do [ -r \"$d/idVendor\" ] || continue; "
    "drv=\"$(for i in \"$d\":*; do [ -L \"$i/driver\" ] && basename \"$(readlink \"$i/driver\")\"; "
    "done 2>/dev/null | sort -u | tr '\\n' ',')\"; "
    "printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"${d##*/}\" "
    "\"$(cat \"$d/busnum\" 2>/dev/null)\" \"$(cat \"$d/devnum\" 2>/dev/null)\" "
    "\"$(cat \"$d/idVendor\" 2>/dev/null)\" \"$(cat \"$d/idProduct\" 2>/dev/null)\" "
    "\"$(cat \"$d/speed\" 2>/dev/null)\" \"$(cat \"$d/bDeviceClass\" 2>/dev/null)\" "
    "\"$(cat \"$d/manufacturer\" 2>/dev/null | tr '\\t' ' ')\" "
    "\"$(cat \"$d/product\" 2>/dev/null | tr '\\t' ' ')\" \"$drv\"; "
    "done"
)

# As root (`id -u` 0) ipmitool runs directly; otherwise through `sudo -n`
# when the grant for that exact command line exists (`sudo -n -l` asks
# without running anything). `timeout` runs a binary, never the root
# shim's `sudo` function — hence deciding here rather than with the usual
# `sudo -n X || X`.
IPMI_SECTION = (
    f"echo ==={IPMI_MARKER}===; "
    "if [ \"$(systemd-detect-virt 2>/dev/null)\" = none ] "
    "&& command -v ipmitool >/dev/null 2>&1 "
    "&& { [ -e /dev/ipmi0 ] || [ -e /dev/ipmi/0 ] || [ -e /dev/ipmidev/0 ]; }; then "
    "I=\"$(command -v ipmitool)\"; R=; "
    "if [ \"$(id -u)\" != 0 ] && command -v sudo >/dev/null 2>&1 "
    f"&& sudo -n -l \"$I\" {IPMI_SDR_ARGS} >/dev/null 2>&1; then R=\"sudo -n\"; fi; "
    f"echo @@SDR; timeout 20 $R \"$I\" {IPMI_SDR_ARGS} 2>/dev/null; "
    f"echo @@SEL; timeout 10 $R \"$I\" {IPMI_SEL_ARGS} 2>/dev/null; "
    "fi"
)

FACTS_SECTIONS = f"{PCI_SECTION}; {USB_SECTION}; {IPMI_SECTION}"

_NAME_AND_ID_RE = re.compile(r"^(.*?)\s*\[([0-9A-Fa-f]{4})\]$")
_HEX_RE = re.compile(r"^(?:0x)?([0-9A-Fa-f]+)$")
# The PCI class codes worth a word in the UI rather than a number.
_PCI_CLASS_NAMES = {
    "01": "Mass storage controller",
    "02": "Network controller",
    "03": "Display controller",
    "04": "Multimedia controller",
    "05": "Memory controller",
    "06": "Bridge",
    "07": "Communication controller",
    "08": "System peripheral",
    "09": "Input device controller",
    "0c": "Serial bus controller",
    "0d": "Wireless controller",
    "10": "Encryption controller",
    "11": "Signal processing controller",
    "12": "Processing accelerator",
}


def _clean(value: str, limit: int = 160) -> str:
    return " ".join(value.split())[:limit]


def _name_and_id(value: str) -> tuple[str, str | None]:
    """`"Intel Corporation [8086]"` -> `("Intel Corporation", "8086")`."""
    match = _NAME_AND_ID_RE.match(value.strip())
    if match is None:
        return _clean(value), None
    return _clean(match.group(1)), match.group(2).lower()


def _hex4(value: str) -> str | None:
    match = _HEX_RE.match(value.strip())
    if match is None:
        return None
    return match.group(1).lower()[-4:].rjust(4, "0")


def _parse_lspci(text: str) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    for block in re.split(r"\n\s*\n", text.strip()):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, sep, value = line.partition(":")
            if sep and key.strip() and key.strip() not in fields:
                fields[key.strip()] = value.strip()
        slot = fields.get("Slot")
        if not slot:
            continue
        class_name, class_id = _name_and_id(fields.get("Class", ""))
        vendor, vendor_id = _name_and_id(fields.get("Vendor", ""))
        device, device_id = _name_and_id(fields.get("Device", ""))
        group = fields.get("IOMMUGroup", "")
        devices.append(
            {
                "slot": _clean(slot, 32),
                "class": class_name or None,
                "class_id": class_id,
                "vendor": vendor or None,
                "vendor_id": vendor_id,
                "device": device or None,
                "device_id": device_id,
                "driver": _clean(fields.get("Driver", ""), 64) or None,
                "iommu_group": int(group) if group.isdecimal() else None,
            }
        )
    return devices


def _parse_pci_sysfs(text: str) -> list[dict[str, Any]]:
    devices: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or not parts[0].strip():
            continue
        slot, klass, vendor_id, device_id, driver = (p.strip() for p in parts)
        class_match = _HEX_RE.match(klass)
        class_hex = class_match.group(1).lower() if class_match else ""
        class_id = class_hex.rjust(6, "0")[:4] if class_hex else None
        devices.append(
            {
                "slot": _clean(slot, 32),
                "class": _PCI_CLASS_NAMES.get(class_id[:2]) if class_id else None,
                "class_id": class_id,
                "vendor": None,
                "vendor_id": _hex4(vendor_id),
                "device": None,
                "device_id": _hex4(device_id),
                "driver": _clean(driver, 64) or None,
                "iommu_group": None,
            }
        )
    return devices


def parse_pci_section(section: str) -> list[dict[str, Any]] | None:
    """The PCI devices, ordered by slot; None when the section is missing
    or listed nothing at all (no PCI bus visible, e.g. some containers)."""
    body, _, iommu_text = section.partition("@@IOMMU")
    body = body.strip()
    if body.startswith("@@LSPCI"):
        devices = _parse_lspci(body[len("@@LSPCI") :])
    elif body.startswith("@@SYSFS"):
        devices = _parse_pci_sysfs(body[len("@@SYSFS") :])
    else:
        return None
    groups: dict[str, int] = {}
    for line in iommu_text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdecimal():
            groups[parts[0]] = int(parts[1])
    for device in devices:
        if device["iommu_group"] is None and device["slot"] in groups:
            device["iommu_group"] = groups[device["slot"]]
    devices.sort(key=lambda d: str(d["slot"]))
    return devices[:MAX_PCI_DEVICES] or None


def parse_usb_section(section: str) -> list[dict[str, Any]] | None:
    """The USB devices other than the Linux root hubs, by bus and device
    number; None when there are none (or no USB at all)."""
    devices: list[dict[str, Any]] = []
    for line in section.splitlines():
        parts = line.split("\t")
        if len(parts) != 10:
            continue
        path, bus, dev, vendor_id, product_id, speed, klass, mfr, product, drivers = (
            p.strip() for p in parts
        )
        vendor_hex = _hex4(vendor_id)
        if vendor_hex is None or vendor_hex == "1d6b":
            continue
        devices.append(
            {
                "path": _clean(path, 32),
                "bus": int(bus) if bus.isdecimal() else None,
                "device": int(dev) if dev.isdecimal() else None,
                "vendor_id": vendor_hex,
                "product_id": _hex4(product_id),
                "manufacturer": _clean(mfr, 96) or None,
                "product": _clean(product, 96) or None,
                "speed_mbps": float(speed) if re.fullmatch(r"\d+(?:\.\d+)?", speed) else None,
                "hub": klass.strip().lower() == "09",
                "drivers": sorted({d for d in drivers.split(",") if d.strip()})[:8],
            }
        )
    devices.sort(key=lambda d: (d["bus"] or 0, d["device"] or 0))
    return devices[:MAX_USB_DEVICES] or None


_SENSOR_VALUE_RE = re.compile(r"^(-?\d+(?:\.\d+)?)\s*(.*)$")
# ipmitool's own status codes: ok, nc (non-critical), cr (critical),
# nr (non-recoverable), ns (no sensor / not readable), lnc/lcr/lnr and
# unc/ucr/unr for the lower/upper thresholds.
_STATUS_LEVEL = {
    "ok": "ok",
    "nc": "warning",
    "lnc": "warning",
    "unc": "warning",
    "cr": "critical",
    "lcr": "critical",
    "ucr": "critical",
    "nr": "critical",
    "lnr": "critical",
    "unr": "critical",
}
_UNITS = {
    "degrees c": "°C",
    "degrees f": "°F",
    "volts": "V",
    "rpm": "RPM",
    "watts": "W",
    "amps": "A",
    "percent": "%",
}


def _parse_sdr(text: str) -> list[dict[str, Any]]:
    sensors: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3 or not parts[0]:
            continue
        name, reading, status = parts[0], parts[1], parts[2].lower()
        if status == "ns":
            continue
        match = _SENSOR_VALUE_RE.match(reading)
        value: float | None = None
        unit: str | None = None
        if match is not None and not reading.lower().startswith("0x"):
            value = float(match.group(1))
            unit_text = match.group(2).strip().lower()
            unit = _UNITS.get(unit_text, _clean(match.group(2), 16) or None)
        sensors.append(
            {
                "name": _clean(name, 64),
                "value": value,
                "unit": unit,
                "reading": None if value is not None else (_clean(reading, 32) or None),
                "status": _STATUS_LEVEL.get(status, "ok" if status in ("", "0x00") else "unknown"),
            }
        )
    return sensors[:MAX_IPMI_SENSORS]


def _parse_sel(text: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5 or not parts[0]:
            continue
        entries.append(
            {
                "id": _clean(parts[0], 16),
                "date": _clean(parts[1], 16) or None,
                "time": _clean(parts[2], 16) or None,
                "sensor": _clean(parts[3], 96) or None,
                "event": _clean(parts[4], 160) or None,
                "direction": _clean(parts[5], 24) if len(parts) > 5 and parts[5] else None,
            }
        )
    entries.reverse()  # newest first
    return entries[:SEL_ENTRIES]


def parse_ipmi_section(section: str) -> dict[str, Any] | None:
    """`{"sensors": [...], "events": [...], "readable": bool}`; None when
    IPMI does not apply (a VM, no ipmitool or no BMC device). `readable`
    False means ipmitool ran but read nothing — usually no root grant."""
    if "@@SDR" not in section:
        return None
    _, _, rest = section.partition("@@SDR")
    sdr_text, _, sel_text = rest.partition("@@SEL")
    sensors = _parse_sdr(sdr_text)
    events = _parse_sel(sel_text)
    return {"sensors": sensors, "events": events, "readable": bool(sensors or events)}


def ipmi_problems(ipmi: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The sensors the BMC itself flags as past a threshold, worst first."""
    rows = [
        s for s in (ipmi or {}).get("sensors") or []
        if isinstance(s, dict) and s.get("status") in ("warning", "critical")
    ]
    return sorted(rows, key=lambda s: (s.get("status") != "critical", str(s.get("name"))))
