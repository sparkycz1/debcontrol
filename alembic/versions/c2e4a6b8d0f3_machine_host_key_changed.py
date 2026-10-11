"""A machine that answers with a different SSH host key than the pinned one

Revision ID: c2e4a6b8d0f3
Revises: b1d3f5a7c9e2
Create Date: 2026-10-11

Two nullable columns; empty until a changed key is noticed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c2e4a6b8d0f3"
down_revision: str | None = "b1d3f5a7c9e2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "machines",
        sa.Column("host_key_changed_fingerprint", sa.String(length=255), nullable=True),
    )
    op.add_column("machines", sa.Column("host_key_changed_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "host_key_changed_at")
    op.drop_column("machines", "host_key_changed_fingerprint")
