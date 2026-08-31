"""machine update run retention policy

Revision ID: 5b78c5e64719
Revises: 9c102e841e79
Create Date: 2026-09-01

`MachineUpdateRun` had no retention policy at all — unlike the audit log
and dashboard trend snapshots, nothing ever purged old rows, and each one
can hold up to ~200KB of stored apt output (see _MAX_STORED_OUTPUT_CHARS in
app/tasks/jobs.py). At fleet sizes in the hundreds/thousands running
recurring scheduled updates, that table grows forever. See
app/db/models/app_settings.py's docstring and
app/tasks/jobs.py's purge_old_machine_update_runs.

Defaults to 90 days (same default as dashboard_trends_retention_days, same
reasoning — operational/diagnostic data, not a compliance record). Existing
deployments get this default applied via `server_default`, same as
dashboard_trends_retention_days's own migration.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "5b78c5e64719"
down_revision: str | None = "9c102e841e79"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column(
            "machine_update_run_retention_days",
            sa.Integer(),
            server_default="90",
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "machine_update_run_retention_days")
