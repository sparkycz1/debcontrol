"""machines: cpu_model, ram_speed_mhz, and per-machine check-interval overrides

Revision ID: f3a91c5d0e2b
Revises: dce686275014
Create Date: 2026-09-01

Two unrelated additions bundled into one migration since both are plain
nullable columns on `machines` with no backfill needed:

- `cpu_model`/`ram_speed_mhz`: two more facts gathered alongside the
  existing `cpu_architecture`/`cpu_cores`/`ram_bytes` (see
  `app.ssh.facts.FACTS_COMMAND`). `ram_speed_mhz` is frequently `None` even
  on a fully-facts-gathered machine — reading it needs `dmidecode`, which
  needs root, which this app doesn't require for facts gathering in
  general (see that module's docstring).
- `reachability_check_interval_seconds`/`facts_refresh_interval_seconds`:
  per-machine overrides of the instance-wide `.env` sweep cadences,
  `NULL` meaning "use the global default" — see `app.tasks.jobs._due_machines`.

All four columns are nullable with no default, so existing rows simply
read as "not yet known" / "use the global default" — no data migration.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f3a91c5d0e2b"
down_revision: str | None = "dce686275014"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("cpu_model", sa.String(length=255), nullable=True))
    op.add_column("machines", sa.Column("ram_speed_mhz", sa.Integer(), nullable=True))
    op.add_column(
        "machines",
        sa.Column("reachability_check_interval_seconds", sa.Integer(), nullable=True),
    )
    op.add_column(
        "machines", sa.Column("facts_refresh_interval_seconds", sa.Integer(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("machines", "facts_refresh_interval_seconds")
    op.drop_column("machines", "reachability_check_interval_seconds")
    op.drop_column("machines", "ram_speed_mhz")
    op.drop_column("machines", "cpu_model")
