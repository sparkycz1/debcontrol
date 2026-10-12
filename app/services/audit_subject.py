"""What an audit entry was about, in a few words.

A translated action label ("Proxmox guest action") says what kind of thing
happened but not to what, so three of them in a row look the same. The
entry's `details` usually know: which guest, which package, which
container. `subject` picks that out — values only, no wording, so it reads
the same in every language.
"""

from __future__ import annotations

from typing import Any

# In order of preference: the first keys present are used.
_KEYS = (
    "vmid",
    "vmids",
    "package",
    "packages",
    "container",
    "unit",
    "service",
    "file",
    "tags",
    "usernames",
    "role",
    "provider",
    "channel",
    "strategy",
    "machine_name",
)
_MAX_PARTS = 2
_MAX_LENGTH = 60


def _text(value: Any) -> str:
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, list | tuple):
        return ", ".join(part for part in (_text(item) for item in value[:5]) if part)
    if isinstance(value, dict):
        return ""
    return str(value).strip()


def subject(details: Any) -> str:
    """A short "111, nginx"-style description from an entry's details, or
    "" when they say nothing specific."""
    if not isinstance(details, dict):
        return ""
    parts: list[str] = []
    for key in _KEYS:
        text = _text(details.get(key))
        if key == "strategy":
            text = text.replace("_", "-")
        if text and text not in parts:
            parts.append(text)
        if len(parts) == _MAX_PARTS:
            break
    joined = ", ".join(parts)
    return joined if len(joined) <= _MAX_LENGTH else joined[: _MAX_LENGTH - 1].rstrip() + "…"
