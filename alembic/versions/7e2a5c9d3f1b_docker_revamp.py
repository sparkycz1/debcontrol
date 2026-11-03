"""Docker revamp: the fleet-wide Docker pages.

- machines.docker_inventory (JSON, NULL until the machine's images,
  volumes, networks and Compose projects are next read).
- ix_docker_jobs_created_at: Docker -> Jobs lists the newest jobs of the
  whole fleet.

Nullable column and an index: nothing changes on upgrade.

Revision ID: 7e2a5c9d3f1b
Revises: 6d1f4b8c2e5a
Create Date: 2026-11-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "7e2a5c9d3f1b"
down_revision: str | None = "6d1f4b8c2e5a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("docker_inventory", sa.JSON(), nullable=True))
    op.create_index("ix_docker_jobs_created_at", "docker_jobs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_docker_jobs_created_at", table_name="docker_jobs")
    op.drop_column("machines", "docker_inventory")
