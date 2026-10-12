"""The backups each Proxmox guest has

Revision ID: e0a2c4d6f8b1
Revises: d9f1b3c5e7a0
Create Date: 2026-10-12

One nullable column, filled by each Proxmox host's next facts refresh.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e0a2c4d6f8b1"
down_revision: str | None = "d9f1b3c5e7a0"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("pve_guest_backups", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "pve_guest_backups")
