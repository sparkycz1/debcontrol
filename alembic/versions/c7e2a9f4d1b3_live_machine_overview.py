"""Live machine overview: CPU breakdown, connectivity from the machine,
network interface kinds, network units per account

Revision ID: c7e2a9f4d1b3
Revises: b3d8f1a6c2e9
Create Date: 2026-11-22 16:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c7e2a9f4d1b3"
down_revision: str | None = "b3d8f1a6c2e9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Nullable with no default, so adding them is instant (and allowed on a
# compressed TimescaleDB hypertable); older samples simply have none.
_SAMPLE_COLUMNS: tuple[tuple[str, bool], ...] = (
    # (name, is_boolean) — every other column is a float.
    ("cpu_user_percent", False),
    ("cpu_system_percent", False),
    ("cpu_iowait_percent", False),
    ("gateway_latency_ms", False),
    ("gateway_loss_percent", False),
    ("internet_latency_ms", False),
    ("internet_loss_percent", False),
    ("dns_ok", True),
    ("dns_ms", False),
    ("ntp_synced", True),
    ("ntp_offset_ms", False),
)


def upgrade() -> None:
    for name, is_boolean in _SAMPLE_COLUMNS:
        column_type = sa.Boolean() if is_boolean else sa.Float()
        op.add_column("machine_monitoring_samples", sa.Column(name, column_type, nullable=True))
    op.add_column("machines", sa.Column("network_links", sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("default_gateway", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("network_units", sa.String(length=8), nullable=True))
    op.add_column(
        "app_settings",
        sa.Column("health_latency_warn_ms", sa.Integer(), nullable=False, server_default="150"),
    )
    op.add_column(
        "app_settings",
        sa.Column("health_latency_critical_ms", sa.Integer(), nullable=False, server_default="500"),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "connectivity_checks_enabled", sa.Boolean(), nullable=False, server_default="true"
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "connectivity_internet_target",
            sa.String(length=253),
            nullable=False,
            server_default="1.1.1.1",
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "connectivity_dns_name",
            sa.String(length=253),
            nullable=False,
            server_default="debian.org",
        ),
    )


def downgrade() -> None:
    for name in (
        "connectivity_dns_name",
        "connectivity_internet_target",
        "connectivity_checks_enabled",
        "health_latency_critical_ms",
        "health_latency_warn_ms",
    ):
        op.drop_column("app_settings", name)
    op.drop_column("users", "network_units")
    op.drop_column("machines", "default_gateway")
    op.drop_column("machines", "network_links")
    for name, _is_boolean in reversed(_SAMPLE_COLUMNS):
        op.drop_column("machine_monitoring_samples", name)
