"""Update runs survive a debcontrol restart

Revision ID: d7e1a3c5b9f2
Revises: c9f25da0b706
Create Date: 2026-10-15

Two nullable columns on machine_update_runs (and an index on the runs
not over yet): the detached job a run
started on its machine, and when the task following it last said so.
Existing runs keep NULL in both (a run already "running" when this lands
is settled by checking its machine, see app.tasks.jobs._resume_machine_update).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d7e1a3c5b9f2"
down_revision: str | None = "c9f25da0b706"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machine_update_runs", sa.Column("remote_job", sa.String(64), nullable=True))
    op.add_column(
        "machine_update_runs",
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_machine_update_runs_open",
        "machine_update_runs",
        ["status"],
        postgresql_where=sa.text("status IN ('pending', 'running')"),
    )


def downgrade() -> None:
    op.drop_index("ix_machine_update_runs_open", table_name="machine_update_runs")
    op.drop_column("machine_update_runs", "heartbeat_at")
    op.drop_column("machine_update_runs", "remote_job")
