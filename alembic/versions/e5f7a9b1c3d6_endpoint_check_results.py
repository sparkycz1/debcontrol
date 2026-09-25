"""endpoint_check_results (per-probe history of endpoint checks)

Revision ID: e5f7a9b1c3d6
Revises: d4e6f8a0b2c5
Create Date: 2026-09-25

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f7a9b1c3d6"
down_revision: str | None = "d4e6f8a0b2c5"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # A new table only — existing checks just start accumulating history
    # from their next probe on.
    op.create_table(
        "endpoint_check_results",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("check_id", sa.Uuid(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(
            ["check_id"],
            ["endpoint_checks.id"],
            name=op.f("fk_endpoint_check_results_check_id_endpoint_checks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_endpoint_check_results")),
    )
    op.create_index(
        "ix_endpoint_check_results_check_id_checked_at",
        "endpoint_check_results",
        ["check_id", "checked_at"],
    )
    op.create_index(
        "ix_endpoint_check_results_checked_at", "endpoint_check_results", ["checked_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_endpoint_check_results_checked_at", table_name="endpoint_check_results")
    op.drop_index(
        "ix_endpoint_check_results_check_id_checked_at", table_name="endpoint_check_results"
    )
    op.drop_table("endpoint_check_results")
