"""background-check settings move from env vars into app_settings

Revision ID: d5f7b9c1e3a6
Revises: c4e6a8b0d2f5
Create Date: 2026-09-12

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d5f7b9c1e3a6"
down_revision: str | None = "c4e6a8b0d2f5"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

# Matches what these used to default to as environment variables — an
# upgrading instance behaves identically until an admin changes one from
# Settings -> Checks & retention.
_DEFAULTS = {
    "ssh_connect_timeout": 10,
    "update_timeout_seconds": 1800,
    "facts_refresh_interval_seconds": 3600,
    "reachability_check_interval_seconds": 60,
    "monitoring_interval_seconds": 120,
    "reachability_check_concurrency": 20,
}


def upgrade() -> None:
    for column_name, default in _DEFAULTS.items():
        op.add_column(
            "app_settings",
            sa.Column(
                column_name, sa.Integer(), nullable=False, server_default=str(default)
            ),
        )


def downgrade() -> None:
    for column_name in _DEFAULTS:
        op.drop_column("app_settings", column_name)
