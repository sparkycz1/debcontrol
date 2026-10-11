"""Guests deliberately left out of Proxmox backups

Revision ID: a0c2e4f6b8d1
Revises: f9b1d3e5a7c0
Create Date: 2026-10-11

One nullable column; empty until a guest is marked on the Proxmox tab.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a0c2e4f6b8d1"
down_revision: str | None = "f9b1d3e5a7c0"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("pve_backup_exempt", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "pve_backup_exempt")
