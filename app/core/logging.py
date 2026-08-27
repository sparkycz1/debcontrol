"""Baseline logging configuration.

Goal: readable structured logs. Never log sensitive values (passwords,
keys, tokens) — keep that in mind in any new code too.
"""

from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(level.upper())

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)

    root.handlers.clear()
    root.addHandler(handler)

    # Quiet down very chatty libraries so our own messages don't get lost.
    logging.getLogger("asyncssh").setLevel(max(logging.INFO, root.level))
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
