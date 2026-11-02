"""Docker → Settings: fleet daemon.json keys and defaults for new containers.

- app_settings: docker_daemon_config, docker_daemon_group_ids (JSON,
  NULL = nothing managed / every machine), docker_default_update_policy,
  docker_default_vulnerability_gate (NULL = off), docker_default_autoheal
  (false).
- machines.docker_daemon_state (JSON, NULL until the settings are first
  written to the machine).

All nullable or with a server default: nothing changes on upgrade.

Revision ID: 6d1f4b8c2e5a
Revises: 5c9e3a7b2d4f
Create Date: 2026-11-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "6d1f4b8c2e5a"
down_revision: str | None = "5c9e3a7b2d4f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("app_settings", sa.Column("docker_daemon_config", sa.JSON(), nullable=True))
    op.add_column("app_settings", sa.Column("docker_daemon_group_ids", sa.JSON(), nullable=True))
    op.add_column(
        "app_settings",
        sa.Column("docker_default_update_policy", sa.String(length=8), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column("docker_default_vulnerability_gate", sa.String(length=16), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "docker_default_autoheal", sa.Boolean(), server_default="false", nullable=False
        ),
    )
    op.add_column("machines", sa.Column("docker_daemon_state", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "docker_daemon_state")
    op.drop_column("app_settings", "docker_default_autoheal")
    op.drop_column("app_settings", "docker_default_vulnerability_gate")
    op.drop_column("app_settings", "docker_default_update_policy")
    op.drop_column("app_settings", "docker_daemon_group_ids")
    op.drop_column("app_settings", "docker_daemon_config")
