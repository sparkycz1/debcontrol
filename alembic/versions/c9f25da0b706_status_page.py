"""Status page settings

Revision ID: c9f25da0b706
Revises: f4dc9569d78d
Create Date: 2026-10-13

Five settings columns; the page is off after the upgrade.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c9f25da0b706"
down_revision: str | None = "f4dc9569d78d"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("status_page_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("app_settings", sa.Column("status_page_token", sa.String(64), nullable=True))
    op.add_column("app_settings", sa.Column("status_page_title", sa.String(120), nullable=True))
    op.add_column("app_settings", sa.Column("status_page_check_ids", sa.JSON(), nullable=True))
    op.add_column("app_settings", sa.Column("status_page_machine_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    for name in (
        "status_page_machine_ids",
        "status_page_check_ids",
        "status_page_title",
        "status_page_token",
        "status_page_enabled",
    ):
        op.drop_column("app_settings", name)
