"""Every `t(request, "...")` key a template uses exists in en.json.

A missing key never fails a request — `t()` falls back to printing the
key itself — so a renamed or removed key only shows up as raw
`notifications.foo.bar` text on a page nobody happened to look at. A key
built at render time (`"prefix." ~ value` / `"prefix." + value`) is
checked as a prefix: at least one key must start with it."""

from __future__ import annotations

import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES = _ROOT / "app" / "web" / "templates"
_EN = _ROOT / "app" / "i18n" / "locales" / "en.json"

# t(request, "key") or t(request, 'key'), optionally followed by `~`/`+`
# (a dynamically completed key).
_CALL = re.compile(r"""\bt\(\s*request\s*,\s*(["'])([A-Za-z0-9_.\-]+)\1\s*([~+])?""")


def _template_keys() -> tuple[set[str], set[str]]:
    exact: set[str] = set()
    prefixes: set[str] = set()
    for path in _TEMPLATES.rglob("*.html"):
        for match in _CALL.finditer(path.read_text(encoding="utf-8")):
            (prefixes if match.group(3) else exact).add(match.group(2))
    return exact, prefixes


def test_every_template_key_exists_in_english():
    strings = json.loads(_EN.read_text(encoding="utf-8"))["strings"]
    exact, prefixes = _template_keys()
    assert exact, "no t() calls found — the regex no longer matches the templates"

    missing = sorted(key for key in exact if key not in strings)
    missing_prefixes = sorted(p for p in prefixes if not any(k.startswith(p) for k in strings))

    assert not missing, f"keys used in templates but missing from en.json: {missing}"
    assert not missing_prefixes, f"no en.json key starts with: {missing_prefixes}"


# `t(request, "...")` in Python code (routes building a flash message, a
# form error...). Same rule; `some.key` is a docstring example.
_PY_EXAMPLES = {"some.key"}
_PY_CALL = re.compile(
    r"""\bt\(\s*request\s*,\s*(["'])([A-Za-z0-9_.\-]+)\1\s*([~+%]|\.format)?"""
)


def test_every_python_key_exists_in_english():
    strings = json.loads(_EN.read_text(encoding="utf-8"))["strings"]
    missing: set[str] = set()
    for path in (_ROOT / "app").rglob("*.py"):
        for match in _PY_CALL.finditer(path.read_text(encoding="utf-8")):
            key = match.group(2)
            if match.group(3) or key in _PY_EXAMPLES:
                continue
            if key not in strings:
                missing.add(f"{path.relative_to(_ROOT)}: {key}")
    assert not missing, f"keys used in Python but missing from en.json: {sorted(missing)}"


def test_every_channel_has_a_send_via_label():
    """The notification rule form builds `notifications.rule.send_via_<channel>`
    for every delivery channel."""
    from app.db.models.notification_log import NotificationDeliveryChannel

    strings = json.loads(_EN.read_text(encoding="utf-8"))["strings"]
    for channel in NotificationDeliveryChannel:
        assert f"notifications.rule.send_via_{channel.value}" in strings
