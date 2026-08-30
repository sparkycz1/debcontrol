"""Guards against every timestamp column silently becoming "timestamp
without time zone" again.

Every timestamp in this app is written and compared as UTC-aware
(`datetime.now(UTC)`, throughout `app/`) — `app.db.base.Base` sets a
`type_annotation_map` so a bare `Mapped[datetime]` infers
`DateTime(timezone=True)` app-wide, matching what every migration in
`alembic/versions/` has always explicitly created in Postgres. Before that
map existed, the ORM layer inferred plain `DateTime()` (no tz) instead —
completely invisible against SQLite (no real tz-aware column type to
enforce a mismatch against) until a real Postgres deployment hit it on
the very first login: SQLAlchemy compiled an explicit
`::TIMESTAMP WITHOUT TIME ZONE` bind-parameter cast from the (wrong)
model-side type, which asyncpg then refused for a tz-aware Python value —
even though the actual column was correctly `timestamptz` all along.

This walks every mapped column rather than hardcoding each one, so a
future column that explicitly re-overrides `DateTime()` without
`timezone=True` fails here immediately.
"""

from __future__ import annotations

from sqlalchemy import DateTime

import app.db.models as models  # noqa: F401 - populates Base.metadata
from app.db.base import Base


def test_every_datetime_column_is_timezone_aware() -> None:
    checked = 0
    for table in Base.metadata.tables.values():
        for column in table.columns:
            col_type = column.type
            if not isinstance(col_type, DateTime):
                continue
            checked += 1
            assert col_type.timezone is True, (
                f"{table.name}.{column.name} is a naive DateTime — asyncpg "
                f"will refuse a tz-aware Python datetime for it. Declare it "
                f"as Mapped[datetime] and let app.db.base.Base's "
                f"type_annotation_map infer DateTime(timezone=True), or "
                f"pass DateTime(timezone=True) explicitly."
            )
    assert checked >= 30
