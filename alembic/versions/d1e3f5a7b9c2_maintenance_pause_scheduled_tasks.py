"""maintenance windows can pause scheduled tasks

Revision ID: d1e3f5a7b9c2
Revises: c9d1e3f5a7b0
Create Date: 2026-09-26

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d1e3f5a7b9c2"
down_revision: str | None = "c9d1e3f5a7b0"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # Existing windows keep doing exactly what they did (mute notifications
    # only); the web form offers the new behaviour ticked for new windows.
    op.add_column(
        "maintenance_windows",
        sa.Column(
            "pause_scheduled_tasks", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )


def downgrade() -> None:
    op.drop_column("maintenance_windows", "pause_scheduled_tasks")
