"""`app.auth.websocket_origin.is_same_origin` — the CSWSH guard shared by
every cookie-authenticated WebSocket."""

from __future__ import annotations

import pytest

from app.auth.websocket_origin import is_same_origin


@pytest.mark.parametrize(
    ("origin", "host"),
    [
        ("https://debcontrol.example.com", "debcontrol.example.com"),
        ("https://debcontrol.example.com", "debcontrol.example.com:443"),
        ("http://localhost:8000", "localhost:8000"),
        ("https://DebControl.Example.com", "debcontrol.example.com"),
        ("http://[::1]:8000", "[::1]:8000"),
    ],
)
def test_same_origin_is_allowed(origin: str, host: str) -> None:
    assert is_same_origin({"origin": origin, "host": host})


@pytest.mark.parametrize(
    ("origin", "host"),
    [
        ("https://evil.example.com", "debcontrol.example.com"),
        ("https://debcontrol.example.com:8443", "debcontrol.example.com"),
        ("http://localhost:9000", "localhost:8000"),
        ("null", "debcontrol.example.com"),
        ("https://debcontrol.example.com", ""),
    ],
)
def test_other_origin_is_refused(origin: str, host: str) -> None:
    assert not is_same_origin({"origin": origin, "host": host})


def test_missing_origin_is_allowed() -> None:
    assert is_same_origin({"host": "debcontrol.example.com"})
