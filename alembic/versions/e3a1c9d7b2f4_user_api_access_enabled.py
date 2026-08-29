"""per-user api_access_enabled flag

Revision ID: e3a1c9d7b2f4
Revises: d6a9c3e2f1b7
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e3a1c9d7b2f4"
down_revision: str | None = "d6a9c3e2f1b7"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("api_access_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("users", "api_access_enabled")
