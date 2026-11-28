"""Machine virtualization kind, vanished-series record; CPU temp 90/97 °C

`machines.virtualization` (nullable, filled by the next facts refresh):
what `systemd-detect-virt` said, so a container's normal failed
/sys/kernel mounts and similar are not reported as problems.

`machines.monitoring_series_seen` (nullable JSON): when each item of the
monitoring samples was last seen, so its history goes a day after it is
gone (app.services.vanished_series); built from history by the first
daily sweep.

The CPU temperature health thresholds move from 80/90 °C to 90/97 °C, but
only on an instance still at the old defaults — a value someone chose
stays as it is.

Revision ID: b8e2c4f6a1d3
Revises: f2b6d8a4c1e7
Create Date: 2026-11-28 11:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b8e2c4f6a1d3"
down_revision: str | None = "f2b6d8a4c1e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("virtualization", sa.String(length=32), nullable=True))
    op.add_column("machines", sa.Column("monitoring_series_seen", sa.JSON(), nullable=True))
    op.alter_column("app_settings", "health_temperature_warn_celsius", server_default="90")
    op.alter_column("app_settings", "health_temperature_critical_celsius", server_default="97")
    op.execute(
        "UPDATE app_settings SET health_temperature_warn_celsius = 90, "
        "health_temperature_critical_celsius = 97 "
        "WHERE health_temperature_warn_celsius = 80 AND health_temperature_critical_celsius = 90"
    )


def downgrade() -> None:
    op.alter_column("app_settings", "health_temperature_warn_celsius", server_default="80")
    op.alter_column("app_settings", "health_temperature_critical_celsius", server_default="90")
    op.drop_column("machines", "monitoring_series_seen")
    op.drop_column("machines", "virtualization")
