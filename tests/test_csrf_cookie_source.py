"""The CSRF cookie is only ever set from the token this server just minted.

`get_or_create_csrf_token` returns `(token_for_template, new_cookie)`. The
first value may be the browser's own `csrftoken` cookie echoed back, so a
route passing it to `set_csrf_cookie` builds a cookie from user input —
CodeQL's py/cookie-injection (alert #167). At runtime both values are the
same whenever a cookie is set, but only `new_cookie` is provably ours, so
that is the one every route must pass.
"""

from __future__ import annotations

import ast
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"


def _offending_calls(source: str) -> list[int]:
    tree = ast.parse(source)
    bad: list[int] = []
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        template_names: set[str] = set()
        for node in ast.walk(func):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "get_or_create_csrf_token"
                and isinstance(node.targets[0], ast.Tuple)
                and isinstance(node.targets[0].elts[0], ast.Name)
            ):
                template_names.add(node.targets[0].elts[0].id)
        bad.extend(
            node.lineno
            for node in ast.walk(func)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "set_csrf_cookie"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Name)
            and node.args[1].id in template_names
        )
    return bad


def test_detects_the_unsafe_shape() -> None:
    src = (
        "def view(request, response):\n"
        "    csrf_token, new_cookie = get_or_create_csrf_token(request)\n"
        "    if new_cookie:\n"
        "        set_csrf_cookie(response, csrf_token)\n"
    )
    assert _offending_calls(src) == [4]
    assert _offending_calls(src.replace("response, csrf_token", "response, new_cookie")) == []


def test_no_route_sets_the_csrf_cookie_from_the_request_value() -> None:
    offenders = [
        f"{path.relative_to(APP_DIR.parent)}:{line}"
        for path in sorted(APP_DIR.rglob("*.py"))
        for line in _offending_calls(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], (
        "set_csrf_cookie() must get the second value from get_or_create_csrf_token(), "
        f"not the first: {offenders}"
    )
