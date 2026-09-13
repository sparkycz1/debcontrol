"""Monitoring sample downsampling settings

Revision ID: c1d5a7e3f9b4
Revises: b8e4c1d9f6a2
Create Date: 2026-09-13

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c1d5a7e3f9b4"
down_revision: str | None = "b8e4c1d9f6a2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column(
            "monitoring_downsample_after_days", sa.Integer(), server_default="7", nullable=True
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "monitoring_downsample_interval_minutes",
            sa.Integer(),
            server_default="60",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "monitoring_downsample_interval_minutes")
    op.drop_column("app_settings", "monitoring_downsample_after_days")
