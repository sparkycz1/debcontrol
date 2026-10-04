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
    "/machine-groups",
    "/security/updates",
    "/checks",
    "/checks/sla",
    "/scheduling",
    "/scheduling/maintenance",
    "/notifications",
    "/notifications/history",
    "/notifications/rules/new",
    "/users",
    "/roles",
    "/audit",
    "/settings",
    "/backup",
    "/account",
    "/search?q=web",
    "/api",
]

# The app's live updates need Redis pub/sub, which this run does not have:
# the socket is refused and the page falls back to polling, by design.
_EXPECTED_NOISE = ("/live/ws",)


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
        if not any(noise in text for noise in _EXPECTED_NOISE):
            problems.append(text)

    page.on("console", on_console)
    page.on("pageerror", lambda error: problems.append(f"uncaught: {error}"))
    page.problems = problems
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


def test_detail_pages_load_without_browser_errors(page: Any) -> None:
    _open(page, _first_href(page, "/checks", "/checks/"))
    _open(page, _first_href(page, "/machine-groups", "/machine-groups/"))


def test_slash_focuses_the_header_search(page: Any) -> None:
    _open(page, "/dashboard")
    page.keyboard.press("/")
    focused = page.evaluate(
        "document.activeElement.hasAttribute('data-global-search')"
    )
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
