"""Postgres-native-enum helper for SQLAlchemy model columns.

`sqlalchemy.Enum(SomePythonEnum, ...)` binds and reads a Python enum member
by its *name* by default (`Permission.MACHINE_VIEW` -> `"MACHINE_VIEW"`) —
even for a `str`-mixed `enum.StrEnum`, which every enum in this codebase
is. Every native Postgres enum type this app's migrations create, though,
is defined with the lowercase `.value` strings as the allowed labels
(e.g. `sa.Enum("apt", "flatpak", "snap", name="package_source")` in
`b4e7a1f9c2d6_machine_packages.py`) — matching each Python enum member's
`.value`, not its `.name`. A bare `Enum(SomeEnum, name=...)` column
definition therefore tries to write/compare the wrong string on Postgres
and fails immediately with `invalid input value for enum ...` on the very
first insert or read.

This is completely invisible against SQLite, which is what this repo's
test suite runs against: SQLAlchemy's SQLite `Enum` implementation is a
`CHECK` constraint it generates itself straight from the Python class
(using the same `.name`-based values), so its own round-trip stays
internally consistent without ever touching what a migration actually
wrote to a real Postgres enum type.

Use `pg_enum(SomeEnum, name="...")` for every native-enum model column
instead of a bare `sqlalchemy.Enum(...)` call — it sets
`values_callable` so binding/reading uses `.value` throughout, matching
what the migrations create.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence

from sqlalchemy import Enum


def _values[E: enum.Enum](enum_cls: type[E]) -> Sequence[str]:
    return [member.value for member in enum_cls]


def pg_enum[E: enum.Enum](enum_cls: type[E], *, name: str) -> Enum:
    return Enum(enum_cls, name=name, native_enum=True, values_callable=_values)
