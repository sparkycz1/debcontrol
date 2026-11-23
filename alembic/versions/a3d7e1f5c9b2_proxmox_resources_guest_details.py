"""Proxmox VE: the cluster's nodes and storages, and each guest's
configuration and IP addresses

`machines.pve_resources` (monitoring sample) and
`machines.pve_guest_details` (facts refresh) are new, nullable JSON
columns; existing machines fill them with their next sample and refresh.

Revision ID: a3d7e1f5c9b2
Revises: e7a3c5d9f2b8
Create Date: 2026-11-22 21:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a3d7e1f5c9b2"
down_revision: str | None = "e7a3c5d9f2b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("pve_resources", sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("pve_guest_details", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "pve_guest_details")
    op.drop_column("machines", "pve_resources")
