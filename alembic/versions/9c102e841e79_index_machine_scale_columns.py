"""index machine name/is_active for fleet-scale queries

Revision ID: 9c102e841e79
Revises: f1a4c7d3b820
Create Date: 2026-09-01

Written by hand rather than `alembic revision --autogenerate` (no local
Postgres to diff against) — two plain B-tree indexes, no data change:

- `machines.name`: the machines list orders by it (`ORDER BY name`) and
  searches it (`machine_search_clause`); unindexed, that's a full table
  scan + sort on every page view once the fleet is in the hundreds/
  thousands.
- `machines.is_active`: every fleet-wide sweep
  (`refresh_all_machine_facts`/`_packages`, `check_all_machine_updates`,
  `ping_all_machines`) filters on this.

`machines.group_id` was originally meant to get one here too, but
`f72dca97d347` (the migration that added the `group_id` column itself)
already creates `ix_machines_group_id` — this migration tried to create it
a second time and failed with `DuplicateTableError` on every deployment
that already had machine groups (i.e. all of them). The model annotation
(`index=True` on `Machine.group_id`) is correct and stays; only the
redundant `create_index` call here was ever wrong.

See app/db/models/machine.py and wiki/Host-Requirements.md.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9c102e841e79"
down_revision: str | None = "f1a4c7d3b820"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_index("ix_machines_name", "machines", ["name"])
    op.create_index("ix_machines_is_active", "machines", ["is_active"])


def downgrade() -> None:
    op.drop_index("ix_machines_is_active", table_name="machines")
    op.drop_index("ix_machines_name", table_name="machines")
