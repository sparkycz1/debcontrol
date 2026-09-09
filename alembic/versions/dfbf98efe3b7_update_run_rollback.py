"""update run package snapshot + rollback linkage

Revision ID: dfbf98efe3b7
Revises: e5f7a9c1d3b6
Create Date: 2026-09-09

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "dfbf98efe3b7"
down_revision: str | None = "e5f7a9c1d3b6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "machine_update_runs", sa.Column("package_snapshot", sa.Text(), nullable=True)
    )
    op.add_column(
        "machine_update_runs", sa.Column("rollback_of_run_id", sa.Uuid(), nullable=True)
    )
    op.create_index(
        op.f("ix_machine_update_runs_rollback_of_run_id"),
        "machine_update_runs",
        ["rollback_of_run_id"],
    )
    op.create_foreign_key(
        op.f("fk_machine_update_runs_rollback_of_run_id_machine_update_runs"),
        "machine_update_runs",
        "machine_update_runs",
        ["rollback_of_run_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_machine_update_runs_rollback_of_run_id_machine_update_runs"),
        "machine_update_runs",
        type_="foreignkey",
    )
    op.drop_index(
        op.f("ix_machine_update_runs_rollback_of_run_id"), table_name="machine_update_runs"
    )
    op.drop_column("machine_update_runs", "rollback_of_run_id")
    op.drop_column("machine_update_runs", "package_snapshot")

