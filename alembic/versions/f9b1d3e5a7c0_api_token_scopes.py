"""API tokens: read-only and machine-group limits

Revision ID: f9b1d3e5a7c0
Revises: e8a0c2d4f6b9
Create Date: 2026-10-04

`api_tokens.read_only` (false for every existing token) and
`api_tokens.machine_group_ids` (NULL = no limit). Existing tokens keep
working exactly as before.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f9b1d3e5a7c0"
down_revision: str | None = "e8a0c2d4f6b9"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "api_tokens",
        sa.Column("read_only", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column("api_tokens", sa.Column("machine_group_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("api_tokens", "machine_group_ids")
    op.drop_column("api_tokens", "read_only")
