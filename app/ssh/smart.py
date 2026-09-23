"""Full S.M.A.R.T. detail per physical disk — the Monitoring tab's
S.M.A.R.T. table and its per-device attribute panel.

Gathered as one extra section of `app.ssh.facts.FACTS_COMMAND` (the facts
cadence, 10 minutes by default) rather than with every 2-minute monitoring
sample: the full `smartctl -a -j` dump is far bigger than the PASSED/FAILED
bit the monitoring sample already keeps for notifications, and none of it
(power-on hours, cycle counts, wear) moves on a minutes scale.

Only runs on bare metal (checked in-shell with `systemd-detect-virt`, the
same probe `Machine.is_physical` comes from — a virtual disk's S.M.A.R.T.
data is meaningless) and only when `smartctl` exists. Needs root on most
systems: the onboarding sudoers grant covers `/usr/sbin/smartctl`; without
it the plain (non-sudo) attempt usually just returns nothing useful.
`sudo -n -l <path>` asks whether the grant exists *before* running, so a
single `smartctl` run happens per disk — its exit status is a bitmask that
is non-zero even on a perfectly readable (just old or error-logged) disk,
so `sudo ... || plain ...` would run it twice and glue two JSON documents
together.
"""

from __future__ import annotations

import json
from typing import Any

SMART_DEVICE_DELIMITER = "@@SMART_DEVICE@@"

SMART_FACTS_SECTION = (
    "echo ===SMART===; "
    "if [ \"$(systemd-detect-virt 2>/dev/null)\" = none ] "
    "&& command -v smartctl >/dev/null 2>&1; then "
    "S=\"$(command -v smartctl)\"; "
    "if sudo -n -l \"$S\" >/dev/null 2>&1; then R=\"sudo -n $S\"; else R=\"$S\"; fi; "
    "for d in $(lsblk -d -n -o NAME,TYPE 2>/dev/null | awk '$2==\"disk\"{print $1}'); do "
    f"echo \"{SMART_DEVICE_DELIMITER} $d\"; "
    "$R -a -j \"/dev/$d\" 2>/dev/null; "
    "done; "
    "fi"
)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _num(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


def _attributes(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The device's own attribute list, in the shape the detail panel shows
    — ATA's classic id/value/worst/threshold/raw table, or NVMe's flat
    health-log dict (no normalized value/threshold, just a raw number)."""
    attributes: list[dict[str, Any]] = []
    ata = doc.get("ata_smart_attributes")
    if isinstance(ata, dict):
        for row in ata.get("table") or []:
            if not isinstance(row, dict):
                continue
            raw = _dict(row.get("raw"))
            attributes.append(
                {
                    "id": row.get("id"),
                    "name": str(row.get("name", "")),
                    "value": _num(row.get("value")),
                    "worst": _num(row.get("worst")),
                    "threshold": _num(row.get("thresh")),
                    "raw": str(raw.get("string", raw.get("value", ""))),
                    "failing": bool(row.get("when_failed")),
                }
            )
    nvme = doc.get("nvme_smart_health_information_log")
    if isinstance(nvme, dict):
        for key, value in nvme.items():
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            elif isinstance(value, dict):
                continue
            attributes.append(
                {
                    "id": None,
                    "name": "".join(part.capitalize() for part in str(key).split("_")),
                    "value": None,
                    "worst": None,
                    "threshold": None,
                    "raw": str(value),
                    "failing": False,
                }
            )
    return attributes


def parse_smart_device(device: str, raw_json: str) -> dict[str, Any] | None:
    """One device's `smartctl -a -j` output → the stored summary. `None`
    when there's nothing usable (no JSON at all, or smartctl couldn't even
    open the device)."""
    try:
        doc = json.loads(raw_json)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None

    status = _dict(doc.get("smart_status"))
    passed = status.get("passed")
    capacity = _dict(doc.get("user_capacity"))
    nvme_capacity = _num(doc.get("nvme_total_capacity"))
    power_on = _dict(doc.get("power_on_time"))
    temperature = _dict(doc.get("temperature"))
    device_info = _dict(doc.get("device"))

    model = doc.get("model_name") or doc.get("model_family") or ""
    if not model and passed is None and not doc.get("serial_number"):
        return None

    protocol = str(device_info.get("protocol") or device_info.get("type") or "").lower()
    kind = "nvme" if "nvme" in protocol else ("sata" if protocol in ("ata", "sat") else protocol)
    rotation = _num(doc.get("rotation_rate"))

    return {
        "device": f"/dev/{device}",
        "model": str(model),
        "serial": str(doc.get("serial_number") or ""),
        "firmware": str(doc.get("firmware_version") or ""),
        "capacity_bytes": _num(capacity.get("bytes")) or nvme_capacity,
        "type": kind or None,
        "rotation_rpm": rotation if rotation else None,
        "passed": passed if isinstance(passed, bool) else None,
        "power_on_hours": _num(power_on.get("hours")),
        "power_cycles": _num(doc.get("power_cycle_count")),
        "temperature_c": _num(temperature.get("current")),
        "attributes": _attributes(doc),
    }


def parse_smart_section(raw: str) -> list[dict[str, Any]] | None:
    """The whole facts SMART section → one summary per readable disk.
    `None` when the section is empty (a VM, no smartctl) — "not
    applicable", as opposed to `[]` ("ran, nothing readable")."""
    if not raw.strip():
        return None
    devices: list[dict[str, Any]] = []
    current_device: str | None = None
    buffer: list[str] = []

    def flush() -> None:
        if current_device is not None and buffer:
            parsed = parse_smart_device(current_device, "\n".join(buffer))
            if parsed is not None:
                devices.append(parsed)

    for line in raw.splitlines():
        if line.startswith(SMART_DEVICE_DELIMITER):
            flush()
            current_device = line[len(SMART_DEVICE_DELIMITER) :].strip() or None
            buffer = []
        else:
            buffer.append(line)
    flush()
    return devices
