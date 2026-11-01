"""Autoheal, endpoint checks from container links, Docker host check.

- docker_container_settings: autoheal (off), autoheal_max_per_hour (3),
  autoheal_restarts, autoheal_gave_up_at.
- endpoint_checks: auto_key (NULL for every existing check) with a
  unique index per source machine.
- app_settings: docker_endpoint_checks (off).
- machines: docker_host_check.

All nullable or with a server default: nothing changes until someone
turns a feature on.

Revision ID: 4b8d2f6a1c3e
Revises: 380462813240
Create Date: 2026-11-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "4b8d2f6a1c3e"
down_revision: str | None = "380462813240"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("docker_container_settings") as batch:
        batch.add_column(
            sa.Column("autoheal", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(
            sa.Column("autoheal_max_per_hour", sa.Integer(), nullable=False, server_default="3")
        )
        batch.add_column(sa.Column("autoheal_restarts", sa.JSON(), nullable=True))
        batch.add_column(
            sa.Column("autoheal_gave_up_at", sa.DateTime(timezone=True), nullable=True)
        )
    with op.batch_alter_table("endpoint_checks") as batch:
        batch.add_column(sa.Column("auto_key", sa.String(length=500), nullable=True))
        batch.create_index(
            "uq_endpoint_checks_auto_key", ["source_machine_id", "auto_key"], unique=True
        )
    with op.batch_alter_table("app_settings") as batch:
        batch.add_column(
            sa.Column(
                "docker_endpoint_checks", sa.Boolean(), nullable=False, server_default=sa.false()
            )
        )
    with op.batch_alter_table("machines") as batch:
        batch.add_column(sa.Column("docker_host_check", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("machines") as batch:
        batch.drop_column("docker_host_check")
    with op.batch_alter_table("app_settings") as batch:
        batch.drop_column("docker_endpoint_checks")
    with op.batch_alter_table("endpoint_checks") as batch:
        batch.drop_index("uq_endpoint_checks_auto_key")
        batch.drop_column("auto_key")
    with op.batch_alter_table("docker_container_settings") as batch:
        batch.drop_column("autoheal_gave_up_at")
        batch.drop_column("autoheal_restarts")
        batch.drop_column("autoheal_max_per_hour")
        batch.drop_column("autoheal")
