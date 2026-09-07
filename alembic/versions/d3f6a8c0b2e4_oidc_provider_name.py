"""oidc_provider_name on app_settings

Revision ID: d3f6a8c0b2e4
Revises: c9e1a3f5d7b2
Create Date: 2026-09-07

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d3f6a8c0b2e4"
down_revision: str | None = "c9e1a3f5d7b2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("oidc_provider_name", sa.String(length=100), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "oidc_provider_name")
