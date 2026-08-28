"""machine update runs

Revision ID: 11549c81e960
Revises: 79297267a7be
Create Date: 2026-08-28

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "11549c81e960"
down_revision: str | None = "79297267a7be"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "machine_update_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("batch_id", sa.Uuid(), nullable=True),
        sa.Column(
            "strategy",
            sa.Enum("dist_upgrade", "full_upgrade", name="upgrade_strategy"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum("pending", "running", "succeeded", "failed", name="update_run_status"),
            nullable=False,
        ),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("error", sa.String(length=1024), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_machine_update_runs_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machine_update_runs")),
    )
    op.create_index(
        op.f("ix_machine_update_runs_machine_id"), "machine_update_runs", ["machine_id"]
    )
    op.create_index(
        "ix_machine_update_runs_batch_id", "machine_update_runs", ["batch_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_machine_update_runs_batch_id", table_name="machine_update_runs")
    op.drop_index(op.f("ix_machine_update_runs_machine_id"), table_name="machine_update_runs")
    op.drop_table("machine_update_runs")
    sa.Enum(name="update_run_status").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="upgrade_strategy").drop(op.get_bind(), checkfirst=True)
