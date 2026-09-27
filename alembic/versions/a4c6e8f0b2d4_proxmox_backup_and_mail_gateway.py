"""Proxmox Backup Server, Mail Gateway and Proxmox VE cluster data

Revision ID: a4c6e8f0b2d4
Revises: f3a5b7c9d1e2
Create Date: 2026-09-27

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a4c6e8f0b2d4"
down_revision: str | None = "f3a5b7c9d1e2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_JSON_COLUMNS = ("pve_cluster", "pve_failed_tasks", "pbs_data", "pmg_data")


def upgrade() -> None:
    # All nullable: filled in by the next facts refresh / monitoring sample.
    for name in _JSON_COLUMNS:
        op.add_column("machines", sa.Column(name, sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("pbs_version", sa.String(length=32), nullable=True))
    op.add_column("machines", sa.Column("pmg_version", sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "pmg_version")
    op.drop_column("machines", "pbs_version")
    for name in reversed(_JSON_COLUMNS):
        op.drop_column("machines", name)
