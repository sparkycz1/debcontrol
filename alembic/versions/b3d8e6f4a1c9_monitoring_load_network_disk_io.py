"""machine_monitoring_samples: CPU load average, network/disk I/O rate;
drop disk-usage% (now redundant with the Overview tab's Facts panel)

Revision ID: b3d8e6f4a1c9
Revises: c2f8b6a1d4e7
Create Date: 2026-09-02

See app.ssh.monitoring's module docstring for why disk *usage* was
dropped from the Monitoring tab's own sample (it already lives on
Machine.filesystems, refreshed on the much slower facts cadence — this
sample is about what's changing right now, not capacity) in favor of
disk *I/O* (throughput) and network I/O, both new here, plus the
1/5/15-minute load averages. This feature shipped only this session and
has no real production data riding on it, so the old `disks` column is
dropped outright rather than kept as unused cruft.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b3d8e6f4a1c9"
down_revision: str | None = "c2f8b6a1d4e7"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machine_monitoring_samples", sa.Column("load1", sa.Float(), nullable=True))
    op.add_column("machine_monitoring_samples", sa.Column("load5", sa.Float(), nullable=True))
    op.add_column("machine_monitoring_samples", sa.Column("load15", sa.Float(), nullable=True))
    op.add_column(
        "machine_monitoring_samples", sa.Column("network_io", sa.JSON(), nullable=True)
    )
    op.add_column("machine_monitoring_samples", sa.Column("disk_io", sa.JSON(), nullable=True))
    op.drop_column("machine_monitoring_samples", "disks")


def downgrade() -> None:
    op.add_column("machine_monitoring_samples", sa.Column("disks", sa.JSON(), nullable=True))
    op.drop_column("machine_monitoring_samples", "disk_io")
    op.drop_column("machine_monitoring_samples", "network_io")
    op.drop_column("machine_monitoring_samples", "load15")
    op.drop_column("machine_monitoring_samples", "load5")
    op.drop_column("machine_monitoring_samples", "load1")
