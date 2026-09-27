"""`app.web.redirects.safe_local_path` — the one open-redirect guard behind
login's `?next=` and the theme toggle's `next` field."""

from __future__ import annotations

import pytest

from app.web.redirects import safe_local_path


@pytest.mark.parametrize(
    "value",
    [
        "https://evil.example",
        "//evil.example",
        "/\\evil.example",
        "/\t/evil.example",
        "/\n/evil.example",
        "evil.example",
        "",
        None,
    ],
)
def test_refuses_anything_that_could_leave_the_site(value):
    assert safe_local_path(value, "/fallback") == "/fallback"


def test_keeps_a_local_path_with_its_query():
    assert safe_local_path("/machines?page=2", "/") == "/machines?page=2"
