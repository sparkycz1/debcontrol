"""UPS state through NUT (Network UPS Tools) — the Monitoring tab's UPS
card, the "UPS on battery" / "power restored" notifications and the
machine health's hardware category.

Read with every monitoring sample (every two minutes by default), so a
power cut is noticed within one interval: `upsc -l` lists the UPSes the
local `upsd` serves and `upsc <name>` prints each one's variables. Both
are plain NUT clients — no root needed, and nothing at all happens on a
machine without NUT (`command -v upsc` first). A machine that is only a
NUT *client* of another machine's UPS shows nothing here; the machine the
UPS is plugged into does.
"""

from __future__ import annotations

import re
from typing import Any

MARKER = "UPS"
MAX_UPSES = 8

SECTION = (
    f"echo ==={MARKER}===; "
    "if command -v upsc >/dev/null 2>&1; then "
    "for u in $(upsc -l 2>/dev/null | head -n 8); do "
    "echo \"@@UPS $u\"; upsc \"$u\" 2>/dev/null; done; fi"
)

_NAME_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,64}$")
_NUMBER_RE = re.compile(r"^-?\d+(?:\.\d+)?$")

# NUT variable -> stored key, numeric ones converted.
_NUMBERS = {
    "battery.charge": "charge_percent",
    "battery.runtime": "runtime_seconds",
    "battery.voltage": "battery_voltage",
    "ups.load": "load_percent",
    "input.voltage": "input_voltage",
    "output.voltage": "output_voltage",
    "ups.realpower": "power_watts",
    "ups.realpower.nominal": "nominal_watts",
    "ups.power.nominal": "nominal_va",
}
_TEXTS = {
    "device.mfr": "manufacturer",
    "ups.mfr": "manufacturer",
    "device.model": "model",
    "ups.model": "model",
    "ups.test.result": "test_result",
    "battery.date": "battery_date",
    "battery.mfr.date": "battery_date",
}


def _ups(name: str, variables: dict[str, str]) -> dict[str, Any]:
    status_raw = " ".join(variables.get("ups.status", "").split())[:64]
    flags = set(status_raw.upper().split())
    entry: dict[str, Any] = {
        "name": name,
        "status": status_raw or None,
        "on_battery": "OB" in flags if flags else None,
        "low_battery": "LB" in flags,
        "replace_battery": "RB" in flags,
        "overloaded": "OVER" in flags,
    }
    for variable, key in _NUMBERS.items():
        value = variables.get(variable, "").strip()
        entry[key] = float(value) if _NUMBER_RE.match(value) else None
    for variable, key in _TEXTS.items():
        value = " ".join(variables.get(variable, "").split())[:96]
        if value and not entry.get(key):
            entry[key] = value
    for key in set(_TEXTS.values()):
        entry.setdefault(key, None)
    return entry


def parse_section(section: str) -> list[dict[str, Any]] | None:
    """One entry per UPS; None when there is no NUT or no local UPS."""
    upses: list[dict[str, Any]] = []
    name: str | None = None
    variables: dict[str, str] = {}
    for line in [*section.splitlines(), "@@UPS"]:
        if line.startswith("@@UPS"):
            if name is not None and variables and len(upses) < MAX_UPSES:
                upses.append(_ups(name, variables))
            candidate = line[len("@@UPS") :].strip()
            name = candidate if _NAME_RE.match(candidate) else None
            variables = {}
            continue
        key, sep, value = line.partition(":")
        if sep and name is not None:
            variables[key.strip()] = value.strip()
    return upses or None


def on_battery_names(upses: list[dict[str, Any]] | None) -> set[str]:
    return {str(u.get("name")) for u in upses or [] if u.get("on_battery")}


def power_changes(
    previous: list[dict[str, Any]] | None, current: list[dict[str, Any]] | None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(UPSes that just went on battery, UPSes back on mains). Nothing when
    either reading is unknown — the first sample after an upgrade never
    reports a UPS that was already on battery."""
    if previous is None or current is None:
        return [], []
    known = {str(u.get("name")) for u in previous}
    before = on_battery_names(previous)
    went = [
        u for u in current
        if u.get("on_battery") and str(u.get("name")) in known and str(u.get("name")) not in before
    ]
    back = [
        u for u in current
        if u.get("on_battery") is False and str(u.get("name")) in before
    ]
    return went, back


def describe(ups: dict[str, Any]) -> str:
    """One plain line for a notification body (English, like every
    default template's details)."""
    parts = [f"UPS {ups.get('name')}: {ups.get('status') or 'unknown status'}"]
    if ups.get("charge_percent") is not None:
        parts.append(f"battery {ups['charge_percent']:g} %")
    if ups.get("runtime_seconds") is not None:
        parts.append(f"about {int(ups['runtime_seconds']) // 60} min left")
    if ups.get("load_percent") is not None:
        parts.append(f"load {ups['load_percent']:g} %")
    return ", ".join(parts)
