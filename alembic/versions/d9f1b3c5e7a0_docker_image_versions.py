"""Which newer version of a container image exists

Revision ID: d9f1b3c5e7a0
Revises: c8e0a2b4d6f9
Create Date: 2026-10-12

One nullable column, filled by the next daily image check.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d9f1b3c5e7a0"
down_revision: str | None = "c8e0a2b4d6f9"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("docker_image_versions", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "docker_image_versions")
