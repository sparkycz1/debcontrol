"""`str.isdigit()` is true for "¹" or "④", which `int()` rejects, so a
parser guarding `int(x)` with it crashes on odd machine output (found by
the `docker_files_listing` fuzz target). `isdecimal()` matches `int()`
exactly; this keeps `isdigit()` out of the app."""

from __future__ import annotations

import base64
from pathlib import Path

from app.ssh import docker_files

_APP = Path(__file__).resolve().parent.parent / "app"


def test_app_code_never_uses_isdigit() -> None:
    offenders = [
        str(path.relative_to(_APP.parent))
        for path in _APP.rglob("*.py")
        if ".isdigit()" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_listing_with_a_superscript_digit_does_not_crash() -> None:
    # The fuzz crash input from the scheduled run on 2026-11-02.
    raw = base64.b64decode(
        "CnwKCgp8fDB8fHx8hQp8fHwKfHx8fHx8MQp8CgoKfHwwfHx8fMUKKnx8MHx8fHyFMXx8Cnx8"
        "wrl8fDB8fIUKfHwwfHx8fHwKfHyFMHx8fHwxfA=="
    )
    docker_files.parse_listing(raw.decode("utf-8", errors="replace"))
