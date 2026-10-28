"""Docker stacks: history and rollback, auto-rollback, vulnerability gate,
SSH deploy keys, more compose files

Revision ID: b7d9e1f3a5c6
Revises: a3c5e7f9b1d2
Create Date: 2026-10-28 14:30:00.000000

- `docker_stacks.keep_history`, `auto_rollback`: opt-in per stack, false
  (what every existing stack did); `vulnerability_gate`: "off".
- `docker_stacks.git_compose_overrides`, `git_ssh_key_encrypted`,
  `git_ssh_public_key`, `git_known_hosts`: nullable, unset for existing
  stacks (one compose file, HTTPS).
- `docker_stacks.deployed_compose`, `deployed_env_encrypted`: nullable;
  filled by the next deploy.
- `docker_stack_versions`: new, empty.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b7d9e1f3a5c6"
down_revision: str | None = "a3c5e7f9b1d2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "docker_stacks",
        sa.Column("keep_history", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "docker_stacks",
        sa.Column("auto_rollback", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "docker_stacks",
        sa.Column(
            "vulnerability_gate", sa.String(length=16), nullable=False, server_default="off"
        ),
    )
    op.add_column("docker_stacks", sa.Column("git_compose_overrides", sa.JSON(), nullable=True))
    op.add_column(
        "docker_stacks", sa.Column("git_ssh_key_encrypted", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "docker_stacks", sa.Column("git_ssh_public_key", sa.String(length=1024), nullable=True)
    )
    op.add_column("docker_stacks", sa.Column("git_known_hosts", sa.Text(), nullable=True))
    op.add_column("docker_stacks", sa.Column("deployed_compose", sa.Text(), nullable=True))
    op.add_column(
        "docker_stacks", sa.Column("deployed_env_encrypted", sa.LargeBinary(), nullable=True)
    )
    op.create_table(
        "docker_stack_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("stack_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("compose_content", sa.Text(), nullable=True),
        sa.Column("env_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("git_url", sa.String(length=512), nullable=True),
        sa.Column("git_branch", sa.String(length=255), nullable=True),
        sa.Column("git_compose_path", sa.String(length=255), nullable=True),
        sa.Column("git_compose_overrides", sa.JSON(), nullable=True),
        sa.Column("commit", sa.String(length=64), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("deployed_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["stack_id"], ["docker_stacks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_docker_stack_versions_stack_created",
        "docker_stack_versions",
        ["stack_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_docker_stack_versions_stack_created", table_name="docker_stack_versions")
    op.drop_table("docker_stack_versions")
    for column in (
        "deployed_env_encrypted",
        "deployed_compose",
        "git_known_hosts",
        "git_ssh_public_key",
        "git_ssh_key_encrypted",
        "git_compose_overrides",
        "vulnerability_gate",
        "auto_rollback",
        "keep_history",
    ):
        op.drop_column("docker_stacks", column)
