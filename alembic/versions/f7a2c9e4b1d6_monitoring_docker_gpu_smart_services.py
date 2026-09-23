"""Monitoring redesign: Docker, per-GPU, S.M.A.R.T. detail, per-service usage

Revision ID: f7a2c9e4b1d6
Revises: e5f8b1c4d7a3
Create Date: 2026-09-23

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f7a2c9e4b1d6"
down_revision: str | None = "e5f8b1c4d7a3"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("smart_devices", sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("docker_status", sa.String(length=16), nullable=True))
    op.add_column("machines", sa.Column("docker_containers", sa.JSON(), nullable=True))

    op.add_column("machine_monitoring_samples", sa.Column("gpus", sa.JSON(), nullable=True))
    op.add_column(
        "machine_monitoring_samples", sa.Column("docker_stats", sa.JSON(), nullable=True)
    )

    op.add_column(
        "machine_services", sa.Column("cpu_usage_nsec", sa.BigInteger(), nullable=True)
    )
    op.add_column(
        "machine_services", sa.Column("active_enter_monotonic", sa.BigInteger(), nullable=True)
    )
    op.add_column("machine_services", sa.Column("cpu_percent", sa.Float(), nullable=True))
    op.add_column("machine_services", sa.Column("cpu_percent_peak", sa.Float(), nullable=True))
    op.add_column("machine_services", sa.Column("memory_bytes", sa.BigInteger(), nullable=True))
    op.add_column(
        "machine_services", sa.Column("memory_peak_bytes", sa.BigInteger(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("machine_services", "memory_peak_bytes")
    op.drop_column("machine_services", "memory_bytes")
    op.drop_column("machine_services", "cpu_percent_peak")
    op.drop_column("machine_services", "cpu_percent")
    op.drop_column("machine_services", "active_enter_monotonic")
    op.drop_column("machine_services", "cpu_usage_nsec")

    op.drop_column("machine_monitoring_samples", "docker_stats")
    op.drop_column("machine_monitoring_samples", "gpus")

    op.drop_column("machines", "docker_containers")
    op.drop_column("machines", "docker_status")
    op.drop_column("machines", "smart_devices")
