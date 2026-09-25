"""endpoint_checks.expected_body (HTTP checks: required response text)

Revision ID: d4e6f8a0b2c5
Revises: c3d5e7f9a1b4
Create Date: 2026-09-25

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e6f8a0b2c5"
down_revision: str | None = "c3d5e7f9a1b4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # Nullable, no default: every existing check keeps its current
    # status-code-only behavior.
    op.add_column(
        "endpoint_checks", sa.Column("expected_body", sa.String(length=200), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("endpoint_checks", "expected_body")
