"""Every `Permission` enum member needs a matching Postgres enum-type label
somewhere in the migration history — see wiki/Development's "Adding a
new permission", step 3. SQLite (what the rest of this suite runs against)
derives its `CHECK` constraint from the live Python enum every time, so it
can never catch a missing migration — a role gaining a permission Postgres
doesn't know about 500s in production with "invalid input value for enum
permission: ..." the first time anyone tries to persist it. This test
statically greps the migration history instead of needing a real Postgres
to catch that class of bug in CI.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.db.models.role import Permission

_VERSIONS_DIR = Path(__file__).resolve().parent.parent / "alembic" / "versions"
_ADD_VALUE_PATTERN = re.compile(r"ALTER TYPE permission ADD VALUE '([^']+)'")
_INITIAL_TUPLE_PATTERN = re.compile(r'"([a-z_]+\.[a-z_]+)"')


def _permission_labels_known_to_migrations() -> set[str]:
    labels: set[str] = set()
    for path in _VERSIONS_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        labels.update(_ADD_VALUE_PATTERN.findall(text))
        if "_PERMISSIONS = (" in text:
            # The original auth/RBAC migration seeds the enum type with a
            # tuple of every permission that existed at the time — pull the
            # string literals out of that tuple specifically, not the whole
            # file (which also has plenty of other quoted strings).
            tuple_text = text.split("_PERMISSIONS = (", 1)[1].split(")", 1)[0]
            labels.update(_INITIAL_TUPLE_PATTERN.findall(tuple_text))
    return labels


def test_every_permission_enum_member_has_a_migration() -> None:
    known = _permission_labels_known_to_migrations()
    current = {p.value for p in Permission}
    missing = current - known
    assert not missing, (
        f"Permission(s) {sorted(missing)} exist in app/db/models/role.py but have no "
        "'ALTER TYPE permission ADD VALUE' migration (or entry in the original "
        "_PERMISSIONS seed) — granting one of these to a role 500s on real Postgres "
        "even though SQLite tests can't see it. See wiki/Development's "
        '"Adding a new permission".'
    )
