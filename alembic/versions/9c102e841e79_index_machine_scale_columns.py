"""index machine name/group_id/is_active for fleet-scale queries

Revision ID: 9c102e841e79
Revises: f1a4c7d3b820
Create Date: 2026-09-01

Written by hand rather than `alembic revision --autogenerate` (no local
Postgres to diff against) — three plain B-tree indexes, no data change:

- `machines.name`: the machines list orders by it (`ORDER BY name`) and
  searches it (`machine_search_clause`); unindexed, that's a full table
  scan + sort on every page view once the fleet is in the hundreds/
  thousands.
- `machines.group_id`: the FK itself has no index by default in Postgres
  (unlike the primary key side) — used by every "machines in this group"
  query and the group list's member-count aggregate
  (`app.web.routes.machine_groups._get_group_member_counts`).
- `machines.is_active`: every fleet-wide sweep
  (`refresh_all_machine_facts`/`_packages`, `check_all_machine_updates`,
  `ping_all_machines`) filters on this.

See app/db/models/machine.py and wiki/Hardware-Requirements.md.
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
    op.create_index("ix_machines_group_id", "machines", ["group_id"])
    op.create_index("ix_machines_is_active", "machines", ["is_active"])


def downgrade() -> None:
    op.drop_index("ix_machines_is_active", table_name="machines")
    op.drop_index("ix_machines_group_id", table_name="machines")
    op.drop_index("ix_machines_name", table_name="machines")
