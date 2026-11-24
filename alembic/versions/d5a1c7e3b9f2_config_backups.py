"""Configuration backups of machines (restic)

A new `config_backup_runs` table (one row per backup), three nullable
columns on `machines` with the newest run's outcome, and the fleet-wide
repository settings on `app_settings` (all nullable, retention with server
defaults). Nothing existing changes; nothing is backed up until someone
sets a repository password.

Revision ID: d5a1c7e3b9f2
Revises: c4e9a2d7f1b5
Create Date: 2026-11-24 18:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d5a1c7e3b9f2"
down_revision: str | None = "c4e9a2d7f1b5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "config_backup_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("snapshot_id", sa.String(length=64), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("file_count", sa.Integer(), nullable=True),
        sa.Column("unreadable_count", sa.Integer(), nullable=True),
        sa.Column("added_bytes", sa.BigInteger(), nullable=True),
        sa.Column("error", sa.String(length=1024), nullable=True),
        sa.Column("started_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_config_backup_runs_machine_created",
        "config_backup_runs",
        ["machine_id", "created_at"],
    )
    op.create_index(
        "ix_config_backup_runs_open",
        "config_backup_runs",
        ["status"],
        postgresql_where=sa.text("status IN ('pending', 'running')"),
    )
    with op.batch_alter_table("machines") as batch:
        batch.add_column(sa.Column("config_backup_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("config_backup_status", sa.String(length=16), nullable=True))
        batch.add_column(
            sa.Column("config_backup_last_success_at", sa.DateTime(timezone=True), nullable=True)
        )
    with op.batch_alter_table("app_settings") as batch:
        batch.add_column(
            sa.Column("config_backup_repository_encrypted", sa.LargeBinary(), nullable=True)
        )
        batch.add_column(
            sa.Column("config_backup_repository_display", sa.String(length=512), nullable=True)
        )
        batch.add_column(
            sa.Column("config_backup_password_encrypted", sa.LargeBinary(), nullable=True)
        )
        batch.add_column(sa.Column("config_backup_env_encrypted", sa.LargeBinary(), nullable=True))
        batch.add_column(
            sa.Column("config_backup_keep_daily", sa.Integer(), server_default="7", nullable=False)
        )
        batch.add_column(
            sa.Column("config_backup_keep_weekly", sa.Integer(), server_default="4", nullable=False)
        )
        batch.add_column(
            sa.Column(
                "config_backup_keep_monthly", sa.Integer(), server_default="12", nullable=False
            )
        )
        batch.add_column(
            sa.Column("config_backup_maintenance_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch.add_column(
            sa.Column("config_backup_maintenance_error", sa.String(length=1000), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("app_settings") as batch:
        for name in (
            "config_backup_maintenance_error",
            "config_backup_maintenance_at",
            "config_backup_keep_monthly",
            "config_backup_keep_weekly",
            "config_backup_keep_daily",
            "config_backup_env_encrypted",
            "config_backup_password_encrypted",
            "config_backup_repository_display",
            "config_backup_repository_encrypted",
        ):
            batch.drop_column(name)
    with op.batch_alter_table("machines") as batch:
        batch.drop_column("config_backup_last_success_at")
        batch.drop_column("config_backup_status")
        batch.drop_column("config_backup_at")
    op.drop_index("ix_config_backup_runs_open", table_name="config_backup_runs")
    op.drop_index("ix_config_backup_runs_machine_created", table_name="config_backup_runs")
    op.drop_table("config_backup_runs")
