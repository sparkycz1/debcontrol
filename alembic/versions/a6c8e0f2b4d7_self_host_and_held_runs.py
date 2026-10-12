"""Boot id of each machine, and update runs held back in a batch

Revision ID: a6c8e0f2b4d7
Revises: f5b7d9e1a3c6
Create Date: 2026-10-12

Two nullable columns. `machines.boot_id` fills in at each machine's next
facts refresh; until then debcontrol does not know which machine it runs
on and behaves as before.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a6c8e0f2b4d7"
down_revision: str | None = "f5b7d9e1a3c6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("boot_id", sa.String(length=36), nullable=True))
    op.create_index("ix_machines_boot_id", "machines", ["boot_id"])
    op.add_column("machine_update_runs", sa.Column("hold_order", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("machine_update_runs", "hold_order")
    op.drop_index("ix_machines_boot_id", table_name="machines")
    op.drop_column("machines", "boot_id")
