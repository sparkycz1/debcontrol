"""Guards against the whole class of bug `app.db.pg_enum` exists to fix:
a native-enum column silently binding a Python enum member's `.name`
(SQLAlchemy's default) instead of its `.value`, which matches nothing a
migration ever created on real Postgres and is completely invisible
against the SQLite backend these tests otherwise run against — see
app/db/pg_enum.py's module docstring for the full story.

This walks every mapped model's columns rather than hardcoding the nine
current ones, so a future native-enum column that reintroduces a bare
`sqlalchemy.Enum(...)` (instead of `pg_enum(...)`) fails here immediately,
without needing a real Postgres to notice.
"""

from __future__ import annotations

from sqlalchemy import Enum as SAEnum

import app.db.models as models  # noqa: F401 - populates Base.metadata
from app.db.base import Base


def test_every_native_enum_column_binds_by_value_not_name() -> None:
    checked = 0
    for table in Base.metadata.tables.values():
        for column in table.columns:
            col_type = column.type
            if not isinstance(col_type, SAEnum) or col_type.enum_class is None:
                continue
            checked += 1
            expected = [member.value for member in col_type.enum_class]
            assert list(col_type.enums) == expected, (
                f"{table.name}.{column.name} binds by name, not value — "
                f"use app.db.pg_enum.pg_enum(...) instead of a bare Enum(...)"
            )
    # Sanity check that this test actually exercised something — if every
    # model stopped using native enums, `checked == 0` would let a bug slip
    # through as trivially "passing".
    assert checked >= 9
