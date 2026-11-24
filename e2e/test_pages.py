"""Browser smoke test: every main page in a real browser, under the real
Content Security Policy.

A CSP violation, a script error or a missing static file is invisible to
the Python test suite — the route returns 200 and the tests pass, while a
real browser shows a dead widget. This opens each page in Chromium and
fails on anything the browser's console reports as an error, then tries
the handful of interactions that only work when the page's scripts ran.

Runs in CI (the `browser` job in `.github/workflows/ci.yml`), not in the
default `pytest` run — it needs Playwright and a browser:

    uv sync --group e2e
    uv run playwright install chromium
    uv run pytest e2e
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from typing import Any

import pytest

playwright_api = pytest.importorskip("playwright.sync_api")

# Pages every signed-in admin can open, by path. Detail pages are reached
# from their list (ids differ per run) — see `_detail_pages`.
PAGES = [
    "/dashboard",
    "/machines",
    "/health",
    "/health/tune-up",
    "/health/tune-up/01890000-0000-7000-8000-000000000001",
    "/terminals",
    "/disks",
    "/machine-groups",
    "/machine-groups/batches",
    "/security/updates",
    "/security/firewall",
    "/checks",
    "/checks/sla",
    "/checks/status-page",
    "/status/e2e-status-page-token",
    "/scheduling",
    "/scheduling/maintenance",
    "/scheduling/calendar",
    "/runbooks",
    "/runbooks/new",
    "/notifications",
    "/notifications/history",
    "/notifications/rules/new",
    "/users",
    "/roles",
    "/audit",
    "/audit/terminal-recordings",
    "/settings",
    "/backup",
    "/backup/machines",
    "/account",
    "/search?q=web",
    "/docker/containers",
    "/docker/stacks",
    "/docker/images",
    "/docker/volumes",
    "/docker/networks",
    "/docker/backups",
    "/docker/hosts",
    "/docker/jobs",
    "/docker/settings",
    "/map",
    "/map/networks",
    "/map/capacity?cores=2&memory_gb=4&disk_gb=20",
    "/api",
]

# The app's live updates need Redis pub/sub, which this run does not have:
# the socket is refused and the page falls back to polling, by design.
_EXPECTED_NOISE = ("/live/ws",)

# xterm.js creates its DOM renderer when the terminal opens, and that one
# injects <style> elements this app's CSP refuses — on purpose: the WebGL
# addon takes over right after and `css/xterm-csp.css` covers the fallback
# (see static/js/terminal.js). Expected on a page with a terminal, and only
# there.
_XTERM_NOISE = "Applying inline style violates"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture(scope="session")
def server() -> Iterator[tuple[str, str]]:
    """The app from `e2e/serve.py`; yields its base URL and a session token."""
    port = _free_port()
    process = subprocess.Popen(  # noqa: S603 - our own module, fixed arguments
        [sys.executable, "-m", "e2e.serve", str(port)],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        token = ""
        for line in process.stdout:
            if line.startswith("SESSION_TOKEN="):
                token = line.strip().removeprefix("SESSION_TOKEN=")
                break
        assert token, "e2e.serve exited before printing a session token"
        base = f"http://127.0.0.1:{port}"
        _wait_until_up(port)
        yield base, token
    finally:
        process.terminate()
        process.wait(timeout=10)


def _wait_until_up(port: int) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    raise AssertionError("the app did not start listening in time")


@pytest.fixture(scope="session")
def browser() -> Iterator[Any]:
    with playwright_api.sync_playwright() as playwright:
        chromium = playwright.chromium.launch()
        yield chromium
        chromium.close()


@pytest.fixture
def page(server: tuple[str, str], browser: Any) -> Iterator[Any]:
    """A signed-in page that collects everything the console calls an error."""
    base, token = server
    context = browser.new_context(base_url=base)
    context.add_cookies([{"name": "session", "value": token, "url": base}])
    page = context.new_page()
    problems: list[str] = []

    def on_console(message: Any) -> None:
        if message.type != "error":
            return
        location = message.location.get("url", "")
        text = f"{message.text} ({location})"
        if not any(noise in text for noise in page.expected_noise):
            problems.append(text)

    page.on("console", on_console)
    page.on("pageerror", lambda error: problems.append(f"uncaught: {error}"))
    page.problems = problems
    page.expected_noise = list(_EXPECTED_NOISE)
    yield page
    context.close()


def _open(page: Any, path: str) -> None:
    response = page.goto(path, wait_until="load")
    status = response.status if response is not None else None
    assert status == 200, f"{path}: HTTP {status}"
    assert page.problems == [], f"{path}: {page.problems}"


@pytest.mark.parametrize("path", PAGES)
def test_page_loads_without_browser_errors(page: Any, path: str) -> None:
    _open(page, path)


def _first_href(page: Any, list_path: str, prefix: str) -> str:
    """The first link on `list_path` that leads to one item's own page —
    `prefix` followed by an id and nothing else (not an export or a
    filter link under the same prefix)."""
    _open(page, list_path)
    href = page.evaluate(
        """(prefix) => {
            const one = new RegExp("^" + prefix + "[0-9a-f-]{36}$");
            const link = [...document.querySelectorAll("main a[href]")].find((a) =>
                one.test(a.getAttribute("href"))
            );
            return link ? link.getAttribute("href") : null;
        }""",
        prefix,
    )
    assert href, f"no link to a single {prefix} item on {list_path}"
    return str(href)


def test_machine_tabs_load_without_browser_errors(page: Any) -> None:
    machine = _first_href(page, "/machines?q=web1", "/machines/")
    # Not Logs or Terminal: both open an SSH session to the machine.
    for tab in ("", "/monitoring", "/updates", "/history"):
        _open(page, machine + tab)


def test_proxmox_pages_load_without_browser_errors(page: Any) -> None:
    host = _first_href(page, "/machines?q=pve1", "/machines/")
    # Not the guest's console: it opens an SSH session to the host.
    _open(page, host + "/proxmox")
    assert page.locator("svg.topology .topo-guest").count() == 2
    for sub in ("/proxmox/guests/101", "/proxmox/guests/200", "/monitoring"):
        _open(page, host + sub)


def test_docker_tab_loads_without_browser_errors(page: Any) -> None:
    machine = _first_href(page, "/machines?q=web1", "/machines/")
    # Only the pages drawn from the database: the rest ask the machine
    # over SSH (inventory, a container's details, Compose projects, the shell).
    for sub in (
        "",
        "/jobs",
        "/host",
        "/stacks/new",
        "/backups",
        "/backups/new",
        "/backups/import",
    ):
        _open(page, machine + "/docker" + sub)


def test_detail_pages_load_without_browser_errors(page: Any) -> None:
    _open(page, _first_href(page, "/checks", "/checks/"))
    _open(page, _first_href(page, "/machine-groups", "/machine-groups/"))
    disk = _first_href(page, "/disks", "/disks/")
    _open(page, disk)
    _open(page, disk + "/report")
    recording = _first_href(page, "/audit/terminal-recordings", "/audit/terminal-recordings/")
    page.expected_noise.append(_XTERM_NOISE)
    _open(page, recording)
    # The player fetched the recording and drew a terminal for it.
    page.locator("#player-play:not([disabled])").wait_for()
    page.locator("#player-play").click()
    page.locator("#terminal-player .xterm").wait_for()
    assert page.problems == []


def test_slash_focuses_the_header_search(page: Any) -> None:
    _open(page, "/dashboard")
    page.keyboard.press("/")
    focused = page.evaluate("document.activeElement.hasAttribute('data-global-search')")
    assert focused


def test_chart_tooltip_legend_and_drag_zoom(page: Any) -> None:
    machine = _first_href(page, "/machines?q=web1", "/machines/")
    _open(page, machine + "/monitoring?range_key=24h")
    chart = page.locator(".chart.chart-zoomable").first
    svg = chart.locator(".chart-svg")
    svg.scroll_into_view_if_needed()
    box = svg.bounding_box()
    assert box is not None

    # Hover: the tooltip script ran.
    page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    assert chart.locator(".chart-tooltip").is_visible()

    # Drag: the page comes back with that stretch as a custom range.
    page.mouse.move(box["x"] + box["width"] * 0.25, box["y"] + 20)
    page.mouse.down()
    page.mouse.move(box["x"] + box["width"] * 0.6, box["y"] + 20, steps=5)
    with page.expect_navigation():
        page.mouse.up()
    assert "start=" in page.url and "end=" in page.url
    assert page.locator("details.range-custom[open]").count() == 1
    assert page.problems == []


def test_terminals_page_tabs_grid_keys_and_reconnect(page: Any) -> None:
    """The Terminals page against a stand-in for the terminal WebSocket
    (no SSH here): panes as tabs and a grid, the key bar's bytes, and a
    dropped session coming back by itself."""
    sockets: list[Any] = []
    received: list[Any] = []

    def fake_terminal(ws: Any) -> None:
        sockets.append(ws)
        ws.on_message(lambda message: received.append(message))
        ws.send(b"hello from the machine\r\n")

    page.route_web_socket("**/terminal/ws", fake_terminal)
    page.expected_noise.append(_XTERM_NOISE)
    _open(page, "/terminals")
    assert page.locator("#terminals-empty").is_visible()

    page.select_option("#terminals-machine", label="web1")
    page.click("#terminals-add")
    first = page.locator(".terminal-pane").first
    first.locator(".xterm-screen").wait_for()
    page.wait_for_function(
        "() => document.querySelector('[data-terminal-status]').textContent.length > 0"
    )
    page.wait_for_timeout(300)
    assert len(sockets) == 1
    assert any(isinstance(m, str) and '"resize"' in m for m in received)
    assert first.locator(".terminal-keys").is_hidden()

    # The key bar (shown by its button on a desktop): Esc, then a sticky Ctrl.
    first.locator("[data-terminal-keys-toggle]").click()
    first.locator('[data-key="esc"]').click()
    first.locator('[data-mod="ctrl"]').click()
    page.keyboard.type("c")
    page.wait_for_timeout(300)
    sent = [bytes(m) for m in received if isinstance(m, bytes | bytearray)]
    assert b"\x1b" in sent and b"\x03" in sent

    # Dropped (not ended): it reconnects by itself, into a new session.
    sockets[0].close(code=1011, reason="SSH connection failed.")
    page.wait_for_function("() => document.querySelectorAll('.xterm').length === 1")
    page.wait_for_timeout(2500)
    assert len(sockets) == 2

    # Ended (exit, the time limit): only the Reconnect button starts again.
    sockets[1].close(code=1000, reason="Session ended.")
    first.locator("[data-terminal-reconnect]").wait_for()
    page.wait_for_timeout(1500)
    assert len(sockets) == 2
    first.locator("[data-terminal-reconnect]").click()
    page.wait_for_timeout(300)
    assert len(sockets) == 3

    # A second pane; tabs show one at a time, the grid both.
    page.select_option("#terminals-machine", label="pve1")
    page.click("#terminals-add")
    assert page.locator(".terminal-tabs [role=tab]").count() == 2
    assert page.locator(".terminal-pane:visible").count() == 1
    page.click('[data-layout="grid"]')
    assert page.locator(".terminal-pane:visible").count() == 2
    assert page.url.count("m=") == 2 and "layout=grid" in page.url

    page.locator(".terminal-pane").nth(1).get_by_role("button", name="Close").click()
    assert page.locator(".terminal-pane").count() == 1
    assert page.url.count("m=") == 1
    assert page.problems == []


def test_config_backup_pages(page: Any) -> None:
    _open(page, "/backup/machines")
    assert page.locator("#config-backup-machines tbody tr").count() >= 2
    machine = _first_href(page, "/machines?q=web1", "/machines/")
    _open(page, machine + "/backup")
    assert page.locator("#config-backup-runs tbody tr").count() == 2
    # The snapshot panel answers (with an error where restic is missing).
    page.locator("#config-backup-snapshots table, #config-backup-snapshots .alert, "
                 "#config-backup-snapshots .empty-state").first.wait_for()
    assert page.problems == []


def test_device_cards_and_firewall_panel(page: Any) -> None:
    machine = _first_href(page, "/machines?q=web1", "/machines/")
    _open(page, machine + "/monitoring")
    for card in ("#ups", "#ipmi", "#pci", "#usb"):
        page.locator(card).wait_for()
    assert "Back-UPS ES 700" in page.locator("#ups").inner_text()
    _open(page, machine + "/security")
    assert "192.0.2.7" in page.locator("#fail2ban-jails").inner_text()
    _open(page, "/security/firewall")
    assert page.locator("#firewall-table tbody tr").count() >= 1
    assert page.problems == []
