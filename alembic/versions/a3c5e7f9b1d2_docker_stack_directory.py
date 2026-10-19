"""Docker stacks: a directory of one's choosing

Revision ID: a3c5e7f9b1d2
Revises: 6e7f3bba7265
Create Date: 2026-10-19 12:00:00.000000

A new stack may go into a directory chosen when it is made instead of
`~/.local/share/debcontrol/stacks/<name>`. Nullable: every existing
stack keeps the default directory it was deployed to.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a3c5e7f9b1d2"
down_revision: str | None = "6e7f3bba7265"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("docker_stacks", sa.Column("directory", sa.String(length=1024), nullable=True))


def downgrade() -> None:
    op.drop_column("docker_stacks", "directory")
