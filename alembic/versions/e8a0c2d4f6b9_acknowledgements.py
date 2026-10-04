"""Acknowledge a problem on a machine or an endpoint check

Revision ID: e8a0c2d4f6b9
Revises: d7f9b1c3e5a8
Create Date: 2026-10-04

Four nullable columns on `machines` and on `endpoint_checks`: when a
problem was acknowledged, until when, by whom and with what note
(`app.services.acknowledgements`). Nothing is acknowledged after the
upgrade, so nothing changes until someone uses it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e8a0c2d4f6b9"
down_revision: str | None = "d7f9b1c3e5a8"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_TABLES = ("machines", "endpoint_checks")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(
            table, sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True)
        )
        op.add_column(
            table, sa.Column("acknowledged_until", sa.DateTime(timezone=True), nullable=True)
        )
        op.add_column(table, sa.Column("acknowledged_by", sa.String(length=255), nullable=True))
        op.add_column(table, sa.Column("acknowledged_note", sa.String(length=500), nullable=True))


def downgrade() -> None:
    for table in _TABLES:
        for column in (
            "acknowledged_note",
            "acknowledged_by",
            "acknowledged_until",
            "acknowledged_at",
        ):
            op.drop_column(table, column)
