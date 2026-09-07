"""Regression guard for a bug found while porting this app's templates to a
sister project (HoneyHive): `machines/terminal.html` references four static
assets (terminal.js, xterm.min.js, xterm-addon-fit.min.js, xterm.css) that
simply never got copied over during that port — every one of them 404'd,
silently, with no error anywhere in Python (the interactive terminal just
never worked in a real browser). The port's test suite never caught it
because, like `tests/test_no_inline_event_handlers.py`'s inline-handler
check, it operates purely at the HTTP-response level (status codes, HTML
content) and never checks that a `src="/static/..."`/`href="/static/..."`
a template renders actually resolves to a real file on disk.

debcontrol itself doesn't have this specific bug — all four terminal
assets are present and git-tracked — but the underlying risk is general:
nothing here previously verified that *any* newly-added
`src`/`href="/static/..."` reference actually exists. This test does.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = _REPO_ROOT / "app" / "web" / "templates"

# Matches src="/static/..." or href="/static/..." (single or double quotes).
# Anything after a "?" (a cache-busting query string, not used today but
# harmless to allow for) or "#" is stripped before checking the path.
_STATIC_REF_RE = re.compile(r"""\b(?:src|href)\s*=\s*["'](/static/[^"'?#]+)""")


def test_every_referenced_static_asset_exists_on_disk() -> None:
    missing = []
    for template_path in TEMPLATES_DIR.rglob("*.html"):
        text = template_path.read_text(encoding="utf-8")
        for match in _STATIC_REF_RE.finditer(text):
            static_path = match.group(1)
            # "/static/x" -> app/web/static/x
            on_disk = _REPO_ROOT / "app" / "web" / static_path.lstrip("/")
            if not on_disk.is_file():
                line_no = text.count("\n", 0, match.start()) + 1
                missing.append(
                    f"{template_path.relative_to(_REPO_ROOT)}:{line_no}: {static_path} "
                    f"(expected at {on_disk.relative_to(_REPO_ROOT)})"
                )
    assert not missing, (
        "Template(s) reference a /static/... asset that doesn't exist on disk — "
        "this 404s silently in a real browser with no error at the Python level "
        "(see this test's own module docstring for the bug this guards against):\n"
        + "\n".join(missing)
    )
