"""reboot required + update availability check columns

Revision ID: 3273688bdc8b
Revises: 11549c81e960
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3273688bdc8b"
down_revision: str | None = "11549c81e960"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("reboot_required", sa.Boolean(), nullable=True))
    op.add_column("machines", sa.Column("upgradable_count", sa.Integer(), nullable=True))
    op.add_column(
        "machines", sa.Column("security_upgradable_count", sa.Integer(), nullable=True)
    )
    op.add_column(
        "machines", sa.Column("updates_checked_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("machines", "updates_checked_at")
    op.drop_column("machines", "security_upgradable_count")
    op.drop_column("machines", "upgradable_count")
    op.drop_column("machines", "reboot_required")
