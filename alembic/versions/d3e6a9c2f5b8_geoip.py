"""GeoIP lookups: AppSettings config + the downloaded database + AuditLogEntry geo columns

Revision ID: d3e6a9c2f5b8
Revises: c1d5a7e3f9b4
Create Date: 2026-09-20

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d3e6a9c2f5b8"
down_revision: str | None = "c1d5a7e3f9b4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column("geoip_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "app_settings", sa.Column("geoip_primary_url_encrypted", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "app_settings", sa.Column("geoip_backup_url_encrypted", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "geoip_refresh_interval_hours", sa.Integer(), server_default="168", nullable=False
        ),
    )

    op.create_table(
        "geoip_database",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_geoip_database")),
    )

    op.add_column(
        "audit_log_entries", sa.Column("geo_country", sa.String(length=100), nullable=True)
    )
    op.add_column(
        "audit_log_entries", sa.Column("geo_country_code", sa.String(length=8), nullable=True)
    )
    op.add_column("audit_log_entries", sa.Column("geo_city", sa.String(length=100), nullable=True))
    op.add_column("audit_log_entries", sa.Column("geo_latitude", sa.Float(), nullable=True))
    op.add_column("audit_log_entries", sa.Column("geo_longitude", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_log_entries", "geo_longitude")
    op.drop_column("audit_log_entries", "geo_latitude")
    op.drop_column("audit_log_entries", "geo_city")
    op.drop_column("audit_log_entries", "geo_country_code")
    op.drop_column("audit_log_entries", "geo_country")

    op.drop_table("geoip_database")

    op.drop_column("app_settings", "geoip_refresh_interval_hours")
    op.drop_column("app_settings", "geoip_backup_url_encrypted")
    op.drop_column("app_settings", "geoip_primary_url_encrypted")
    op.drop_column("app_settings", "geoip_enabled")
