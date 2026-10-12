"""Proxmox snapshot before an update

Revision ID: b7d9f1a3c5e8
Revises: a6c8e0f2b4d7
Create Date: 2026-10-12

New columns only; `snapshot_before` defaults to false, so every existing
and scheduled update keeps running without a snapshot.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7d9f1a3c5e8"
down_revision: str | None = "a6c8e0f2b4d7"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_RUN_COLUMNS = (
    sa.Column("snapshot_name", sa.String(length=64), nullable=True),
    sa.Column("snapshot_host_id", sa.Uuid(), nullable=True),
    sa.Column("snapshot_node", sa.String(length=63), nullable=True),
    sa.Column("snapshot_type", sa.String(length=8), nullable=True),
    sa.Column("snapshot_vmid", sa.Integer(), nullable=True),
    sa.Column("snapshot_note", sa.String(length=32), nullable=True),
    sa.Column("snapshot_rolled_back_at", sa.DateTime(), nullable=True),
)


def upgrade() -> None:
    op.add_column(
        "machine_update_runs",
        sa.Column("snapshot_before", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    for column in _RUN_COLUMNS:
        op.add_column("machine_update_runs", column.copy())
    op.create_foreign_key(
        "fk_machine_update_runs_snapshot_host_id",
        "machine_update_runs",
        "machines",
        ["snapshot_host_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column("machines", sa.Column("pve_debcontrol_snapshots", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "pve_debcontrol_snapshots")
    op.drop_constraint(
        "fk_machine_update_runs_snapshot_host_id", "machine_update_runs", type_="foreignkey"
    )
    for column in reversed(_RUN_COLUMNS):
        op.drop_column("machine_update_runs", column.name)
    op.drop_column("machine_update_runs", "snapshot_before")
