"""machines: post-onboarding readiness check columns

Revision ID: c2f8b6a1d4e7
Revises: a7c4e91d5f3b
Create Date: 2026-09-02

`readiness_checked_at`/`readiness_missing` — see app.ssh.readiness and
Machine's own docstring on these columns. Both nullable, no backfill.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c2f8b6a1d4e7"
down_revision: str | None = "a7c4e91d5f3b"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "machines", sa.Column("readiness_checked_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("machines", sa.Column("readiness_missing", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "readiness_missing")
    op.drop_column("machines", "readiness_checked_at")
