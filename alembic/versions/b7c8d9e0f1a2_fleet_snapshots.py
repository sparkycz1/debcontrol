"""daily fleet snapshots for the dashboard trend chart(s)

Revision ID: b7c8d9e0f1a2
Revises: a1b2c3d4e5f6
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7c8d9e0f1a2"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "fleet_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("total_machines", sa.Integer(), nullable=False),
        sa.Column("online_machines", sa.Integer(), nullable=False),
        sa.Column("offline_machines", sa.Integer(), nullable=False),
        sa.Column("needs_updates", sa.Integer(), nullable=False),
        sa.Column("needs_security_updates", sa.Integer(), nullable=False),
        sa.Column("needs_reboot", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_fleet_snapshots")),
        sa.UniqueConstraint("snapshot_date", name=op.f("uq_fleet_snapshots_snapshot_date")),
    )
    op.create_index(
        op.f("ix_fleet_snapshots_snapshot_date"), "fleet_snapshots", ["snapshot_date"]
    )

    op.add_column(
        "app_settings",
        sa.Column(
            "dashboard_trends_retention_days",
            sa.Integer(),
            server_default="90",
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "dashboard_trends_retention_days")

    op.drop_index(op.f("ix_fleet_snapshots_snapshot_date"), table_name="fleet_snapshots")
    op.drop_table("fleet_snapshots")
