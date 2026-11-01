"""Docker image packages (SBOM).

- docker_image_packages: new, empty; filled by every image scan from now
  on (Trivy's package list), searched by name prefix.

Revision ID: 5c9e3a7b2d4f
Revises: 4b8d2f6a1c3e
Create Date: 2026-11-01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "5c9e3a7b2d4f"
down_revision: str | None = "4b8d2f6a1c3e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "docker_image_packages",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("name_key", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("purl", sa.String(length=512), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["docker_image_scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_docker_image_packages_name_key",
        "docker_image_packages",
        ["name_key"],
        postgresql_ops={"name_key": "text_pattern_ops"},
    )
    op.create_index("ix_docker_image_packages_scan", "docker_image_packages", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_docker_image_packages_scan", table_name="docker_image_packages")
    op.drop_index("ix_docker_image_packages_name_key", table_name="docker_image_packages")
    op.drop_table("docker_image_packages")
