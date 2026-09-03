"""scheduled AI fleet summary (fleet_summaries table, app_settings.fleet_summary_*)

Revision ID: b7c9e2a4f6d1
Revises: a4f7d1c8e6b3
Create Date: 2026-09-04

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7c9e2a4f6d1"
down_revision: str | None = "a4f7d1c8e6b3"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    fleet_summary_frequency = sa.Enum(
        "disabled", "daily", "weekly", name="fleet_summary_frequency"
    )
    fleet_summary_frequency.create(op.get_bind(), checkfirst=True)

    op.add_column(
        "app_settings",
        sa.Column(
            "fleet_summary_frequency",
            fleet_summary_frequency,
            server_default="disabled",
            nullable=False,
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column("fleet_summary_provider_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_app_settings_fleet_summary_provider_id",
        "app_settings",
        "ai_provider_configs",
        ["fleet_summary_provider_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column(
        "app_settings",
        sa.Column("fleet_summary_model_id", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "fleet_summary_retention_days", sa.Integer(), server_default="180", nullable=True
        ),
    )

    op.create_table(
        "fleet_summaries",
        sa.Column("id", sa.Uuid(), primary_key=True, default=uuid.uuid4),
        sa.Column("frequency", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("provider_kind", sa.String(length=32), nullable=False),
        sa.Column("model_id", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index(
        "ix_fleet_summaries_created_at", "fleet_summaries", ["created_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_fleet_summaries_created_at", table_name="fleet_summaries")
    op.drop_table("fleet_summaries")
    op.drop_column("app_settings", "fleet_summary_retention_days")
    op.drop_column("app_settings", "fleet_summary_model_id")
    op.drop_constraint(
        "fk_app_settings_fleet_summary_provider_id", "app_settings", type_="foreignkey"
    )
    op.drop_column("app_settings", "fleet_summary_provider_id")
    op.drop_column("app_settings", "fleet_summary_frequency")
    sa.Enum(name="fleet_summary_frequency").drop(op.get_bind(), checkfirst=True)
