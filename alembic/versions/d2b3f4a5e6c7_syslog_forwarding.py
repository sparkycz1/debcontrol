"""syslog forwarding of audit log entries (app_settings.syslog_*)

Revision ID: d2b3f4a5e6c7
Revises: c1a2f3e4d5b6
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d2b3f4a5e6c7"
down_revision: str | None = "c1a2f3e4d5b6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    syslog_protocol = sa.Enum("udp", "tcp", "tls", name="syslog_protocol")
    syslog_protocol.create(op.get_bind(), checkfirst=True)

    op.add_column(
        "app_settings",
        sa.Column("syslog_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("app_settings", sa.Column("syslog_host", sa.String(length=255), nullable=True))
    op.add_column(
        "app_settings",
        sa.Column("syslog_port", sa.Integer(), server_default="514", nullable=False),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "syslog_protocol", syslog_protocol, server_default="udp", nullable=False
        ),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "syslog_protocol")
    op.drop_column("app_settings", "syslog_port")
    op.drop_column("app_settings", "syslog_host")
    op.drop_column("app_settings", "syslog_enabled")
    sa.Enum(name="syslog_protocol").drop(op.get_bind(), checkfirst=True)
