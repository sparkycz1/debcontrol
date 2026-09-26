"""sign-in policy settings (session lifetime, lockout, allowed networks)

Revision ID: c9d1e3f5a7b0
Revises: b8c0d2e4f6a9
Create Date: 2026-09-26

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c9d1e3f5a7b0"
down_revision: str | None = "b8c0d2e4f6a9"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

# The values that used to be hardcoded (app.auth.sessions / app.auth.login),
# so an upgrading instance behaves identically until an admin changes one.
_DEFAULTS = {
    "session_idle_timeout_minutes": 720,
    "session_absolute_max_hours": 720,
    "login_max_failed_attempts": 5,
    "login_lockout_minutes": 15,
}


def upgrade() -> None:
    for column_name, default in _DEFAULTS.items():
        op.add_column(
            "app_settings",
            sa.Column(column_name, sa.Integer(), nullable=False, server_default=str(default)),
        )
    op.add_column("app_settings", sa.Column("login_allowed_networks", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("app_settings", "login_allowed_networks")
    for column_name in _DEFAULTS:
        op.drop_column("app_settings", column_name)
