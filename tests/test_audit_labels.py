"""Every audit action code the app records has a translated label
(`audit.action_label.<code>`, used by `app.web.templating.audit_text`) in
every shipped language. A missing label isn't an error at runtime — the
Audit log falls back to the English summary — so without this test a new
action would quietly stay untranslated."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
# One character class, no nested quantifier (linear time).
_ACTION = re.compile(r'action=(f?)"([a-z_.{}]+)"')


def _strings(code: str) -> dict[str, str]:
    path = _ROOT / "app" / "i18n" / "locales" / f"{code}.json"
    strings: dict[str, str] = json.loads(path.read_text(encoding="utf-8"))["strings"]
    return strings


def _audit_codes() -> tuple[set[str], set[str]]:
    """`(exact codes, prefixes of f-string codes)` from every
    `log_event(..., action="...")` call."""
    exact: set[str] = set()
    prefixes: set[str] = set()
    for path in (_ROOT / "app").rglob("*.py"):
        for match in _ACTION.finditer(path.read_text(encoding="utf-8")):
            code = match.group(2)
            if "." not in code or code.startswith("."):
                continue
            if match.group(1) and "{" in code:
                prefixes.add(code.split(".{")[0])
            elif "{" not in code:
                exact.add(code)
    return exact, prefixes


def _labelled(code: str, strings: dict[str, str]) -> bool:
    while code:
        if f"audit.action_label.{code}" in strings:
            return True
        code = code.rpartition(".")[0]
    return False


@pytest.mark.parametrize("locale", ["en", "cs"])
def test_every_audit_action_has_a_label(locale):
    strings = _strings(locale)
    exact, prefixes = _audit_codes()
    assert len(exact) > 50, "the action-code scan no longer finds log_event calls"

    missing = sorted(c for c in exact if not _labelled(c, strings))
    # `machine.power.{action.value}`: each concrete action has its own label.
    missing_prefixes = sorted(
        p
        for p in prefixes
        if not _labelled(p, strings)
        and not any(k.startswith(f"audit.action_label.{p}.") for k in strings)
    )
    assert not missing, f"audit actions without a {locale} label: {missing}"
    assert not missing_prefixes, f"no {locale} label under: {missing_prefixes}"
