"""Regression guard for the live-update WebSocket wiring — the browser
half (`app/web/static/js/live-updates.js`), every template that opts into
it, and the server route it connects to (`app/web/routes/live_ws.py`).
These are three separately-edited files agreeing on the same data
attribute names and URL shape, with nothing enforcing that at runtime — a
mismatch fails silently (the socket simply never opens, or the script
finds no anchor and no-ops entirely), with no error anywhere a human
would notice short of watching the browser console. See
wiki/Architecture's "Live updates are a doorbell, not a data feed"
section.

This is exactly the class of bug a sibling project (derived from this
one) shipped from its very first commit: a renamed data attribute the
JS's selector was never updated to match, silently leaving every page's
live-update socket a permanent no-op behind an always-on polling
fallback, with zero errors anywhere, for as long as nobody happened to
open the browser console.
"""

from __future__ import annotations

from pathlib import Path

from app.main import app
from app.web.routes import live_ws

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES_DIR = _REPO_ROOT / "app" / "web" / "templates"
_LIVE_UPDATES_JS = (_REPO_ROOT / "app" / "web" / "static" / "js" / "live-updates.js").read_text(
    encoding="utf-8"
)

_DATA_ATTR_ID = "data-live-machine-id"
_DATA_ATTR_NAME = "data-live-machine-name"


def test_live_updates_js_selector_matches_the_data_attribute_every_page_sets():
    assert f'"[{_DATA_ATTR_ID}]"' in _LIVE_UPDATES_JS
    assert f'getAttribute("{_DATA_ATTR_ID}")' in _LIVE_UPDATES_JS
    assert f'getAttribute("{_DATA_ATTR_NAME}")' in _LIVE_UPDATES_JS


def test_live_updates_js_builds_the_url_the_live_ws_route_actually_serves():
    # The JS builds this by string interpolation, so there's nothing to
    # literally execute here — assert on the literal template instead...
    assert "/machines/${encodeURIComponent(machineId)}/live/ws" in _LIVE_UPDATES_JS

    # ...and that a websocket route genuinely exists at that same shape
    # (the Python-side equivalent of the JS's `{machineId}` placeholder) —
    # `url_path_for` on the route's own function name is Starlette's public
    # route-resolution API, so this stays correct across an internal
    # routing refactor rather than reaching into `app.router.routes`.
    assert app.url_path_for("machine_live_websocket", machine_id="123") == "/machines/123/live/ws"


def test_every_template_that_includes_live_updates_js_sets_the_data_attribute():
    """Walks every template under app/web/templates/ — a template that
    `<script src=".../live-updates.js">`s in must also set
    `data-live-machine-id` (and `-name`) somewhere in the same file, or
    the script loads and immediately no-ops with no indication why."""
    offenders = []
    for template_path in _TEMPLATES_DIR.rglob("*.html"):
        text = template_path.read_text(encoding="utf-8")
        if "live-updates.js" not in text:
            continue
        if _DATA_ATTR_ID not in text:
            offenders.append(str(template_path.relative_to(_REPO_ROOT)))

    assert offenders == [], (
        f"these templates include live-updates.js but never set {_DATA_ATTR_ID}, "
        f"so their live-update socket silently no-ops: {offenders}"
    )


def test_at_least_the_known_machine_pages_wire_up_live_updates():
    """Not exhaustive by design (the test above already is) — this just
    keeps the three pages this feature was actually built for
    (`wiki/Architecture`'s own list) from quietly losing the include
    during an unrelated template refactor."""
    for relative_path in (
        "machines/detail.html",
        "machines/monitoring.html",
        "machines/update_history.html",
    ):
        text = (_TEMPLATES_DIR / relative_path).read_text(encoding="utf-8")
        assert "live-updates.js" in text, f"{relative_path} no longer includes live-updates.js"
        assert _DATA_ATTR_ID in text, f"{relative_path} no longer sets {_DATA_ATTR_ID}"


_LIVE_FLEET_JS = (_REPO_ROOT / "app" / "web" / "static" / "js" / "live-fleet.js").read_text(
    encoding="utf-8"
)


def test_live_fleet_js_connects_to_the_fleet_route():
    assert "/machines/live/ws" in _LIVE_FLEET_JS
    assert app.url_path_for("fleet_live_websocket") == "/machines/live/ws"


def test_the_fleet_route_is_matched_before_the_per_machine_one():
    """Otherwise "/machines/live/ws" would be tried as machine id "live"."""
    paths = [getattr(route, "path", None) for route in live_ws.router.routes]
    assert paths.index("/machines/live/ws") < paths.index("/machines/{machine_id}/live/ws")


def test_the_machine_list_opts_into_live_fleet_updates():
    template = (_TEMPLATES_DIR / "machines" / "list.html").read_text(encoding="utf-8")
    assert "js/live-fleet.js" in template
    assert 'id="machine-results" data-live-fleet' in template
    assert '"machine-results"' in _LIVE_FLEET_JS
    assert '"[data-live-fleet]"' in _LIVE_FLEET_JS
