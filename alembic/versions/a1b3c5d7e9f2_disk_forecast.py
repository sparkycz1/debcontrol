"""Machine.disk_forecast (disk-full forecast)

Revision ID: a1b3c5d7e9f2
Revises: f7a2c9e4b1d6
Create Date: 2026-09-25

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b3c5d7e9f2"
down_revision: str | None = "f7a2c9e4b1d6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("disk_forecast", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "disk_forecast")
