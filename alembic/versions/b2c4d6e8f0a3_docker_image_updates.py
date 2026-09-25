"""Machine.docker_image_updates / docker_images_checked_at

Revision ID: b2c4d6e8f0a3
Revises: a1b3c5d7e9f2
Create Date: 2026-09-25

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2c4d6e8f0a3"
down_revision: str | None = "a1b3c5d7e9f2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("docker_image_updates", sa.JSON(), nullable=True))
    op.add_column(
        "machines", sa.Column("docker_images_checked_at", sa.DateTime(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("machines", "docker_images_checked_at")
    op.drop_column("machines", "docker_image_updates")
