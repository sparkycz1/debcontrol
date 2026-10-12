"""What a machine's firmware says it is: vendor, model, serial number
(the facts' HARDWARE section; see `app.services.hardware_inventory`)."""

from __future__ import annotations

# Firmware fields vendors leave unfilled.
_PLACEHOLDERS = frozenset(
    {
        "",
        "0",
        "none",
        "n/a",
        "na",
        "default string",
        "not specified",
        "not applicable",
        "system product name",
        "system manufacturer",
        "system serial number",
        "to be filled by o.e.m.",
        "o.e.m.",
        "unknown",
        "123456789",
    }
)


def clean_firmware_value(value: str) -> str | None:
    text = " ".join(value.split())[:128]
    return None if text.lower() in _PLACEHOLDERS else text


def parse_hardware(section: str) -> dict[str, str | None]:
    """`{"vendor", "model", "serial"}` from the facts' `key=value` lines."""
    found: dict[str, str | None] = {"vendor": None, "model": None, "serial": None}
    for line in section.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() in found:
            found[key.strip()] = clean_firmware_value(value)
    return found
