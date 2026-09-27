"""The one check for a user-supplied redirect target (`?next=`, a form's
`next` field) — shared so every caller refuses the same open-redirect
tricks."""

from __future__ import annotations


def safe_local_path(value: str | None, default: str) -> str:
    """`value` if it's a same-site absolute path, else `default`.

    Refused: anything not starting with `/`, a protocol-relative `//host`,
    any backslash (browsers read `/\\evil.example` as `//evil.example`) and
    any control character (a tab/newline is stripped before the URL is
    parsed, turning `/\\t/evil.example` into `//evil.example`)."""
    if (
        value
        and value.startswith("/")
        and not value.startswith("//")
        and "\\" not in value
        and not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)
    ):
        return value
    return default
