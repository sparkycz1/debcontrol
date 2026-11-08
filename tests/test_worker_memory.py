"""The Celery worker's memory guards (0.137.0): every forked child used to
import all four AI SDKs (~110 MB each) through app.tasks.jobs, and nothing
kept a long-running child from growing."""

from __future__ import annotations

import gc
import subprocess
import sys

from app.core.lazy_import import lazy_import
from app.tasks import celery_app as celery_module

_AI_SDKS = ("anthropic", "openai", "openrouter", "google.genai")


def test_worker_task_modules_do_not_import_the_ai_sdks() -> None:
    # A fresh interpreter: this test process may have imported them already.
    code = (
        "import sys\n"
        "import app.tasks.celery_app as c\n"
        "for name in c.celery_app.conf.include:\n"
        "    __import__(name)\n"
        f"loaded = [m for m in {_AI_SDKS!r} if m in sys.modules\n"
        "          and type(sys.modules[m]).__name__ != '_LazyModule']\n"
        "print(','.join(loaded))\n"
    )
    result = subprocess.run(  # noqa: S603 — fixed argv, our own interpreter
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=120
    )
    assert result.stdout.strip() == ""


def test_lazy_import_loads_on_first_attribute_access() -> None:
    module = lazy_import("tests.lazy_import_target")
    # importlib.util's stand-in until something is read from it.
    assert type(module).__name__ == "_LazyModule"
    assert module.LOADED is True
    assert type(module).__name__ == "module"


def test_lazy_import_returns_an_already_imported_module() -> None:
    import json

    assert lazy_import("json") is json


def test_worker_children_are_recycled() -> None:
    conf = celery_module.celery_app.conf
    assert conf.worker_max_tasks_per_child == 200
    assert conf.worker_max_memory_per_child == 400 * 1024


def test_parent_heap_is_frozen_before_forking_a_child() -> None:
    try:
        celery_module._freeze_parent_heap()
        assert gc.get_freeze_count() > 0
    finally:
        gc.unfreeze()
