"""ldap_tls_verify flag on app_settings

Revision ID: a4c8e2f6b0d9
Revises: f4a7c9e1b3d5
Create Date: 2026-09-06

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a4c8e2f6b0d9"
down_revision: str | None = "f4a7c9e1b3d5"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("ldap_tls_verify", sa.Boolean(), server_default=sa.true(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "ldap_tls_verify")
