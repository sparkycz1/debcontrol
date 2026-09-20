"""Physical-machine hardware monitoring: Machine.is_physical + sensors/fans/SMART/power

Revision ID: e5f8b1c4d7a3
Revises: d3e6a9c2f5b8
Create Date: 2026-09-20

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f8b1c4d7a3"
down_revision: str | None = "d3e6a9c2f5b8"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("is_physical", sa.Boolean(), nullable=True))

    op.add_column(
        "machine_monitoring_samples", sa.Column("sensor_temps", sa.JSON(), nullable=True)
    )
    op.add_column(
        "machine_monitoring_samples", sa.Column("sensor_fans", sa.JSON(), nullable=True)
    )
    op.add_column(
        "machine_monitoring_samples", sa.Column("smart_disks", sa.JSON(), nullable=True)
    )
    op.add_column(
        "machine_monitoring_samples", sa.Column("cpu_energy_uj", sa.BigInteger(), nullable=True)
    )
    op.add_column(
        "machine_monitoring_samples", sa.Column("gpu_power_watts", sa.Float(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("machine_monitoring_samples", "gpu_power_watts")
    op.drop_column("machine_monitoring_samples", "cpu_energy_uj")
    op.drop_column("machine_monitoring_samples", "smart_disks")
    op.drop_column("machine_monitoring_samples", "sensor_fans")
    op.drop_column("machine_monitoring_samples", "sensor_temps")

    op.drop_column("machines", "is_physical")
