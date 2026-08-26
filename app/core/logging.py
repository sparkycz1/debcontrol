"""Základní konfigurace logování.

Cíl: čitelné strukturované logy, žádné citlivé údaje (hesla, klíče, tokeny)
se nikdy nelogují — dbej na to i v nově přidávaném kódu.
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

    # Utlumit velmi ukecané knihovny, ať v logu nezaniknou naše zprávy.
    logging.getLogger("asyncssh").setLevel(max(logging.INFO, root.level))
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
