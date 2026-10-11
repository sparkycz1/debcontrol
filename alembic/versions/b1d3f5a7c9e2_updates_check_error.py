"""Why the last update check failed

Revision ID: b1d3f5a7c9e2
Revises: a0c2e4f6b8d1
Create Date: 2026-10-11

One nullable column; empty until a check fails.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b1d3f5a7c9e2"
down_revision: str | None = "a0c2e4f6b8d1"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "machines", sa.Column("updates_check_error", sa.String(length=1024), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("machines", "updates_check_error")
