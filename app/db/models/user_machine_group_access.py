"""Per-user, per-machine-group visibility scoping — an orthogonal layer on
top of the role/permission matrix in `app.db.models.role`.

Permissions answer *what* an account may do (`machine.view`,
`action.power`, ...). This answers *to which machines and groups* it may do
it. The two are deliberately independent: a role stays a reusable,
resource-grained capability set, and the scope is a per-account property an
admin sets alongside `User.api_access_enabled` (see `app/web/routes/users.py`).

One row = "this user may see this group, and the machines in it".

**The default is unrestricted, and that's the whole backward-compatibility
story:** a user with *zero* rows here is not scoped at all and sees
everything, exactly as before this table existed. A user with one or more
rows is restricted to exactly those groups. Machines with no group
(`Machine.group_id IS NULL`) are never visible to a restricted user — only
explicitly granted groups are, so "unrestricted" can never be reached by
accident from a partial grant. The migration that adds this table therefore
needs no backfill: every existing account starts unrestricted.

Enforcement lives in one place, `app.services.access_scope`; nothing else
should query this table directly.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class UserMachineGroupAccess(Base):
    """A plain many-to-many join row, not an entity — there is nothing to
    say about one of these beyond the pair it names, so it carries no id,
    no timestamps, and no relationships (the grant set is always replaced
    wholesale, never edited row by row; see `app.services.access_scope`)."""

    __tablename__ = "user_machine_group_access"

    # ON DELETE CASCADE on both sides: a grant is meaningless once either
    # end is gone, and leaving stale rows behind would silently widen or
    # narrow somebody's scope the next time an id was reused.
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machine_groups.id", ondelete="CASCADE"), primary_key=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"UserMachineGroupAccess(user_id={self.user_id!r}, group_id={self.group_id!r})"
        )
