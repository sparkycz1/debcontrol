"""Base class for SQLAlchemy models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, MetaData
from sqlalchemy.orm import DeclarativeBase

# Naming convention for constraints — without it, Alembic autogenerate
# produces inconsistent, hard-to-reference names for indexes and keys.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    # Every timestamp in this app is written and compared as UTC-aware
    # (`datetime.now(UTC)`, throughout `app/`) — a bare `Mapped[datetime]`
    # would otherwise infer plain `DateTime()` (Postgres "timestamp without
    # time zone"), which asyncpg flatly refuses to accept a tz-aware value
    # for ("can't subtract offset-naive and offset-aware datetimes"). This
    # was invisible against SQLite (no real tz-aware column type to enforce
    # the mismatch against) until a real Postgres deployment hit it on the
    # very first login. See the migration that added `timezone=True` to
    # every existing timestamp column for the one-time data-side fix this
    # pairs with.
    type_annotation_map = {datetime: DateTime(timezone=True)}
