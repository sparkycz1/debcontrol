"""Docker upgrade #4: cancelling jobs, backup commands and test restores.

- docker_jobs.cancel_requested_by / cancel_requested_at: someone asked a
  running job to stop (a cancelled job's status is the new "cancelled").
- docker_backups.hook_container / pre_command / post_command: commands
  run with `docker exec` around a backup.
- docker_backups.last_verify_at / last_verify_status / last_verify_details:
  the last test restore.

Every column is nullable: existing jobs and backups are unchanged.

Revision ID: d9f1a3b5c7e9
Revises: c8e0f2a4b6d7
Create Date: 2026-10-28
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d9f1a3b5c7e9"
down_revision: str | None = "c8e0f2a4b6d7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("docker_jobs", sa.Column("cancel_requested_by", sa.String(255), nullable=True))
    op.add_column(
        "docker_jobs", sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("docker_backups", sa.Column("hook_container", sa.String(255), nullable=True))
    op.add_column("docker_backups", sa.Column("pre_command", sa.Text(), nullable=True))
    op.add_column("docker_backups", sa.Column("post_command", sa.Text(), nullable=True))
    op.add_column(
        "docker_backups", sa.Column("last_verify_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("docker_backups", sa.Column("last_verify_status", sa.String(16), nullable=True))
    op.add_column("docker_backups", sa.Column("last_verify_details", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("docker_backups", "last_verify_details")
    op.drop_column("docker_backups", "last_verify_status")
    op.drop_column("docker_backups", "last_verify_at")
    op.drop_column("docker_backups", "post_command")
    op.drop_column("docker_backups", "pre_command")
    op.drop_column("docker_backups", "hook_container")
    op.drop_column("docker_jobs", "cancel_requested_at")
    op.drop_column("docker_jobs", "cancel_requested_by")
