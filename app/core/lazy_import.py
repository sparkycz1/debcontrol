"""Import a heavy module on first use instead of at import time.

`app.tasks.jobs` (and through it every Celery worker process) reaches
`app.ai.providers`, whose four AI SDKs cost about 110 MB of memory and two
seconds per process, while most installs never call an AI provider and the
ones that do call it from a single task. Each forked worker child would pay
for them anyway. `lazy_import` returns a stand-in module that runs the real
import the first time one of its attributes is read, using the standard
library's own `importlib.util.LazyLoader`.

Use it together with a `TYPE_CHECKING` import, so type checkers still see
the real module:

    if TYPE_CHECKING:
        import anthropic
    else:
        anthropic = lazy_import("anthropic")
"""

from __future__ import annotations

import importlib.util
import sys
from types import ModuleType


def lazy_import(name: str) -> ModuleType:
    """The module called `name`, loaded only when first used. An already
    imported module is returned as it is."""
    if (module := sys.modules.get(name)) is not None:
        return module
    spec = importlib.util.find_spec(name)
    if spec is None or spec.loader is None:
        raise ModuleNotFoundError(f"No module named {name!r}", name=name)
    loader = importlib.util.LazyLoader(spec.loader)
    spec.loader = loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module
