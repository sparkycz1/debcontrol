"""Network card addresses of each machine

Revision ID: f4dc9569d78d
Revises: 723c4691dbaa
Create Date: 2026-10-13

One nullable column, filled by each machine's next facts refresh.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f4dc9569d78d"
down_revision: str | None = "723c4691dbaa"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("mac_addresses", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "mac_addresses")
