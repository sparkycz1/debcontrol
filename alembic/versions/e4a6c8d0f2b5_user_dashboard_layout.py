"""Each account's own Dashboard layout

Revision ID: e4a6c8d0f2b5
Revises: d3f5b7c9e1a4
Create Date: 2026-10-11

One nullable column; NULL is the default Dashboard, as before.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e4a6c8d0f2b5"
down_revision: str | None = "d3f5b7c9e1a4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("dashboard_layout", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "dashboard_layout")
