"""Private registries, shared variables, adopted containers and drift.

- docker_registries / docker_registry_logins: registry logins (fleet-wide,
  per machine group or per machine) and whether `docker login` worked on
  each machine.
- docker_variables: shared variables and secrets for stacks.
- docker_stacks: shared_variables, replace_container, drift_check (off),
  drift_status / drift_details / drift_checked_at — all nullable or with
  a server default, so existing stacks keep working unchanged.

Revision ID: 380462813240
Revises: f2b4d6e8a0c1
Create Date: 2026-11-01
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa

from alembic import op

revision: str = "380462813240"
down_revision: str | None = "f2b4d6e8a0c1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _scope_columns() -> list[sa.Column[Any]]:
    return [
        sa.Column(
            "group_id",
            sa.Uuid(),
            sa.ForeignKey("machine_groups.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "machine_id",
            sa.Uuid(),
            sa.ForeignKey("machines.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("scope_key", sa.String(length=40), nullable=False, server_default=""),
    ]


def upgrade() -> None:
    op.create_table(
        "docker_registries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("server", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("password_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False, server_default=""),
        *_scope_columns(),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_docker_registries")),
        sa.UniqueConstraint("server", "scope_key", name="uq_docker_registries_server_scope"),
    )
    op.create_index(
        op.f("ix_docker_registries_group_id"), "docker_registries", ["group_id"]
    )
    op.create_index(
        op.f("ix_docker_registries_machine_id"), "docker_registries", ["machine_id"]
    )

    op.create_table(
        "docker_registry_logins",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "machine_id",
            sa.Uuid(),
            sa.ForeignKey("machines.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("server", sa.String(length=255), nullable=False),
        sa.Column(
            "registry_id",
            sa.Uuid(),
            sa.ForeignKey("docker_registries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("message", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_docker_registry_logins")),
        sa.UniqueConstraint(
            "machine_id", "server", name="uq_docker_registry_logins_machine_server"
        ),
    )
    op.create_index(
        op.f("ix_docker_registry_logins_registry_id"), "docker_registry_logins", ["registry_id"]
    )

    op.create_table(
        "docker_variables",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("value_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("secret", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("description", sa.String(length=255), nullable=False, server_default=""),
        *_scope_columns(),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("updated_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_docker_variables")),
        sa.UniqueConstraint("name", "scope_key", name="uq_docker_variables_name_scope"),
    )
    op.create_index(op.f("ix_docker_variables_group_id"), "docker_variables", ["group_id"])
    op.create_index(op.f("ix_docker_variables_machine_id"), "docker_variables", ["machine_id"])

    with op.batch_alter_table("docker_stacks") as batch:
        batch.add_column(sa.Column("shared_variables", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("replace_container", sa.String(length=255), nullable=True))
        batch.add_column(
            sa.Column("drift_check", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.add_column(sa.Column("drift_status", sa.String(length=16), nullable=True))
        batch.add_column(sa.Column("drift_details", sa.JSON(), nullable=True))
        batch.add_column(
            sa.Column("drift_checked_at", sa.DateTime(timezone=True), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("docker_stacks") as batch:
        for column in (
            "drift_checked_at",
            "drift_details",
            "drift_status",
            "drift_check",
            "replace_container",
            "shared_variables",
        ):
            batch.drop_column(column)
    op.drop_table("docker_variables")
    op.drop_table("docker_registry_logins")
    op.drop_table("docker_registries")
