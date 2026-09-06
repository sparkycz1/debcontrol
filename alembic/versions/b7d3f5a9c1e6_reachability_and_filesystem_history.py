"""machine_reachability_samples table, filesystems column on
machine_monitoring_samples

Revision ID: b7d3f5a9c1e6
Revises: a4c8e2f6b0d9
Create Date: 2026-09-06

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7d3f5a9c1e6"
down_revision: str | None = "a4c8e2f6b0d9"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "machine_monitoring_samples",
        sa.Column("filesystems", sa.JSON(), nullable=True),
    )

    op.create_table(
        "machine_reachability_samples",
        sa.Column("id", sa.Uuid(), primary_key=True, default=uuid.uuid4),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reachable", sa.Boolean(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_machine_reachability_samples_machine_id_machines"),
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_machine_reachability_samples_machine_id",
        "machine_reachability_samples",
        ["machine_id"],
    )
    op.create_index(
        "ix_machine_reachability_samples_machine_id_checked_at",
        "machine_reachability_samples",
        ["machine_id", "checked_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_machine_reachability_samples_machine_id_checked_at",
        table_name="machine_reachability_samples",
    )
    op.drop_index(
        "ix_machine_reachability_samples_machine_id",
        table_name="machine_reachability_samples",
    )
    op.drop_table("machine_reachability_samples")
    op.drop_column("machine_monitoring_samples", "filesystems")
