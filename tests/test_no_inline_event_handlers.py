"""Regression guard for a real bug: `machines/monitoring.html`'s time-range
`<select>` used to have `onchange="this.form.submit()"` — an inline event
handler attribute, which this app's CSP (`script-src 'self'`, no
'unsafe-inline') silently strips at the browser layer. The route/template
logic was entirely correct; changing the dropdown just did nothing, with no
error visible anywhere in the Python-level test suite (see
`wiki/Architecture.md`'s CSP note: this class of bug is invisible except as
a "blank widget" in a real browser). Fixed via `data-autosubmit` +
`static/js/auto-submit.js`, the same delegated-listener pattern
`confirm.js` already uses for `data-confirm`/`onsubmit`.

This test scans every template's source for any `on<word>="..."` attribute
so a new one can't sneak back in unnoticed the same way.
"""

from __future__ import annotations

import re
from pathlib import Path

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "app" / "web" / "templates"

# Matches on<letters>="..." or on<letters>='...' — case-insensitive since
# HTML attribute names are case-insensitive.
_INLINE_HANDLER_RE = re.compile(r"""\bon[a-z]+\s*=\s*["']""", re.IGNORECASE)


def test_no_template_has_an_inline_event_handler_attribute() -> None:
    offenders = []
    for path in TEMPLATES_DIR.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        for match in _INLINE_HANDLER_RE.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{path.relative_to(TEMPLATES_DIR)}:{line_no}: {match.group(0)}")
    assert not offenders, (
        "Inline event handler attribute(s) found — silently stripped by this "
        "app's CSP (script-src 'self', no 'unsafe-inline'), so the handler "
        "just never fires in a real browser. Use a data-* attribute plus a "
        "delegated listener in a vendored .js file instead (see "
        "static/js/confirm.js or auto-submit.js):\n" + "\n".join(offenders)
    )
