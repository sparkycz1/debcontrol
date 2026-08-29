"""uptime/cpu architecture/process count facts + pending-package name lists

Revision ID: c5f8b2e6a1d4
Revises: b4e7a1f9c2d6
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c5f8b2e6a1d4"
down_revision: str | None = "b4e7a1f9c2d6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("cpu_architecture", sa.String(length=64), nullable=True))
    op.add_column("machines", sa.Column("uptime_seconds", sa.BigInteger(), nullable=True))
    op.add_column("machines", sa.Column("process_count", sa.Integer(), nullable=True))

    op.add_column("machines", sa.Column("apt_upgradable_packages", sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("flatpak_upgradable_packages", sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("snap_upgradable_packages", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "snap_upgradable_packages")
    op.drop_column("machines", "flatpak_upgradable_packages")
    op.drop_column("machines", "apt_upgradable_packages")

    op.drop_column("machines", "process_count")
    op.drop_column("machines", "uptime_seconds")
    op.drop_column("machines", "cpu_architecture")
