"""filesystem usage + network interfaces facts, held apt packages

Revision ID: d6a9c3e2f1b7
Revises: c5f8b2e6a1d4
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d6a9c3e2f1b7"
down_revision: str | None = "c5f8b2e6a1d4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("filesystems", sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("network_interfaces", sa.JSON(), nullable=True))

    op.add_column(
        "machine_packages",
        sa.Column("held", sa.Boolean(), server_default=sa.false(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("machine_packages", "held")

    op.drop_column("machines", "network_interfaces")
    op.drop_column("machines", "filesystems")
