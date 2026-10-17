"""Docker: jobs, image scans, container settings, stacks, restic backups

Revision ID: 6e7f3bba7265
Revises: c4e6a8b0d2f1
Create Date: 2026-10-17

New tables and two nullable columns on `machines` (a machine simply has
no scan summary or backup yet); nothing existing changes.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "6e7f3bba7265"
down_revision: str | None = "c4e6a8b0d2f1"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def _created_at() -> sa.Column[Any]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )


def _updated_at() -> sa.Column[Any]:
    return sa.Column(
        "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )


def _machine_fk() -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE")


def upgrade() -> None:
    op.add_column("machines", sa.Column("docker_vulnerabilities", sa.JSON(), nullable=True))
    op.add_column(
        "machines",
        sa.Column("docker_backup_ok_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "docker_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("params", sa.JSON(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("error", sa.String(length=1024), nullable=True),
        sa.Column("started_by", sa.String(length=255), nullable=True),
        sa.Column("batch_id", sa.Uuid(), nullable=True),
        sa.Column("ref_id", sa.Uuid(), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        _machine_fk(),
        sa.PrimaryKeyConstraint("id", name="pk_docker_jobs"),
    )
    op.create_index("ix_docker_jobs_machine_created", "docker_jobs", ["machine_id", "created_at"])
    op.create_index("ix_docker_jobs_status", "docker_jobs", ["status"])

    op.create_table(
        "docker_image_scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("image_id", sa.String(length=80), nullable=False),
        sa.Column("image_ref", sa.String(length=512), nullable=False),
        sa.Column("scanners", sa.JSON(), nullable=True),
        sa.Column("counts", sa.JSON(), nullable=True),
        sa.Column("vulnerabilities", sa.JSON(), nullable=True),
        sa.Column("errors", sa.JSON(), nullable=True),
        sa.Column(
            "scanned_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        _machine_fk(),
        sa.PrimaryKeyConstraint("id", name="pk_docker_image_scans"),
        sa.UniqueConstraint("machine_id", "image_id", name="uq_docker_image_scans_machine_image"),
    )

    op.create_table(
        "docker_container_settings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("auto_update", sa.Boolean(), nullable=False),
        sa.Column("vulnerability_gate", sa.String(length=16), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=True),
        _updated_at(),
        _machine_fk(),
        sa.PrimaryKeyConstraint("id", name="pk_docker_container_settings"),
        sa.UniqueConstraint(
            "machine_id", "name", name="uq_docker_container_settings_machine_name"
        ),
    )

    op.create_table(
        "docker_stacks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("compose_content", sa.Text(), nullable=True),
        sa.Column("env_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("git_url", sa.String(length=512), nullable=True),
        sa.Column("git_branch", sa.String(length=255), nullable=True),
        sa.Column("git_compose_path", sa.String(length=255), nullable=True),
        sa.Column("git_token_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("auto_sync", sa.Boolean(), nullable=False),
        sa.Column("webhook_token_hash", sa.String(length=64), nullable=True),
        sa.Column("webhook_last_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deployed_commit", sa.String(length=64), nullable=True),
        sa.Column("deployed_hash", sa.String(length=64), nullable=True),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=16), nullable=True),
        sa.Column("last_error", sa.String(length=1024), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        _created_at(),
        _updated_at(),
        _machine_fk(),
        sa.PrimaryKeyConstraint("id", name="pk_docker_stacks"),
        sa.UniqueConstraint("machine_id", "name", name="uq_docker_stacks_machine_name"),
        sa.UniqueConstraint("webhook_token_hash", name="uq_docker_stacks_webhook_token_hash"),
    )

    op.create_table(
        "docker_backups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("repository_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("repository_display", sa.String(length=512), nullable=False),
        sa.Column("password_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("env_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("volumes", sa.JSON(), nullable=False),
        sa.Column("paths", sa.JSON(), nullable=False),
        sa.Column("excludes", sa.JSON(), nullable=False),
        sa.Column("stop_containers", sa.Boolean(), nullable=False),
        sa.Column("keep_last", sa.Integer(), nullable=True),
        sa.Column("keep_daily", sa.Integer(), nullable=True),
        sa.Column("keep_weekly", sa.Integer(), nullable=True),
        sa.Column("keep_monthly", sa.Integer(), nullable=True),
        sa.Column("last_backup_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_backup_status", sa.String(length=16), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_snapshot_id", sa.String(length=64), nullable=True),
        sa.Column("last_backup_bytes", sa.BigInteger(), nullable=True),
        sa.Column("last_error", sa.String(length=1024), nullable=True),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_check_status", sa.String(length=16), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        _created_at(),
        _updated_at(),
        _machine_fk(),
        sa.PrimaryKeyConstraint("id", name="pk_docker_backups"),
        sa.UniqueConstraint("machine_id", "name", name="uq_docker_backups_machine_name"),
    )


def downgrade() -> None:
    op.drop_table("docker_backups")
    op.drop_table("docker_stacks")
    op.drop_table("docker_container_settings")
    op.drop_table("docker_image_scans")
    op.drop_index("ix_docker_jobs_status", table_name="docker_jobs")
    op.drop_index("ix_docker_jobs_machine_created", table_name="docker_jobs")
    op.drop_table("docker_jobs")
    op.drop_column("machines", "docker_backup_ok_at")
    op.drop_column("machines", "docker_vulnerabilities")
