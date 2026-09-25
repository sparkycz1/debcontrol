"""timezone-aware timestamps for endpoint_checks and machines.docker_images_checked_at

The endpoint checks and Docker image-update migrations created these as
plain `timestamp`, while every model timestamp is `DateTime(timezone=True)`
(`app.db.base.Base.type_annotation_map`) and `alembic check` flags the
drift. Postgres has been storing the UTC values the app writes, so each
column is converted by reading its existing value *as UTC* — no value
changes.

Revision ID: f6a8b0c2d4e7
Revises: e5f7a9b1c3d6
Create Date: 2026-09-25

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f6a8b0c2d4e7"
down_revision: str | None = "e5f7a9b1c3d6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_COLUMNS = (
    ("endpoint_checks", "last_checked_at", True),
    ("endpoint_checks", "cert_expires_at", True),
    ("endpoint_checks", "cert_warned_for", True),
    ("endpoint_checks", "created_at", False),
    ("machines", "docker_images_checked_at", True),
)


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests) has no separate timezone-aware type.
    for table, column, nullable in _COLUMNS:
        op.alter_column(
            table,
            column,
            type_=sa.DateTime(timezone=True),
            existing_type=sa.DateTime(),
            existing_nullable=nullable,
            postgresql_using=f"{column} AT TIME ZONE 'UTC'",
        )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, column, nullable in _COLUMNS:
        op.alter_column(
            table,
            column,
            type_=sa.DateTime(),
            existing_type=sa.DateTime(timezone=True),
            existing_nullable=nullable,
            postgresql_using=f"{column} AT TIME ZONE 'UTC'",
        )
