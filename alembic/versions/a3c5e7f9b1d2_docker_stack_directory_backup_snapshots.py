"""Docker: a stack directory of one's choosing, backups of other hosts

Revision ID: a3c5e7f9b1d2
Revises: 6e7f3bba7265
Create Date: 2026-10-19 12:00:00.000000

- `docker_stacks.directory`: a new stack may go into a directory chosen
  when it is made instead of `~/.local/share/debcontrol/stacks/<name>`.
  Nullable: every existing stack keeps the default directory it was
  deployed to.
- `docker_backups.all_snapshots`: list every snapshot in the repository
  (another machine's, an older install's), not just the backup's own.
  Defaults to false, which is what every existing backup did.
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
    op.add_column(
        "docker_backups",
        sa.Column("all_snapshots", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("docker_backups", "all_snapshots")
    op.drop_column("docker_stacks", "directory")
