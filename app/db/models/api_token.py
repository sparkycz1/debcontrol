"""Per-user API tokens for the read-only REST API (`app.web.routes.api_v1`)
and, as an alternative to the shared `INFORM_TOKEN`, for `POST /api/inform`
— see that route's module docstring.

A token authorizes at most what its owning user's role currently permits,
checked fresh on every request (`app.auth.api_tokens.get_user_for_api_token`)
rather than snapshotting permissions at creation time — revoking a role's
permission (or deactivating the user) takes effect on the token immediately,
the same as it would for that user's browser session.

A token can be narrowed further when it is created, never widened:
`read_only` refuses every request that would change something, and
`machine_group_ids` limits the machines and groups it sees to those groups
(on top of the owner's own group scope) — see `app.auth.dependencies.
get_api_token_user` and `app.services.access_scope.allowed_group_ids`.

Self-service, like TOTP enrollment: a user creates and revokes their own
tokens from "My account"; nobody (including debcontrol itself, after
creation) can read the raw value again — only `token_hash` (SHA-256, same
scheme as `UserSession.token_hash`) and a cosmetic `token_prefix` are
stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user: Mapped[User] = relationship(back_populates="api_tokens")

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # First few characters of the raw token, kept in the clear purely so the
    # owner can tell their tokens apart in the list without ever seeing the
    # full value again — like GitHub's "ghp_1234...".
    token_prefix: Mapped[str] = mapped_column(String(12), nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # NULL = never expires.
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # Only GET/HEAD requests are accepted with this token.
    read_only: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    # Machine-group ids (as strings) this token is limited to. NULL = no
    # limit beyond the owner's own; an empty list (every listed group since
    # deleted) sees no machines at all rather than falling back to "all".
    machine_group_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    @property
    def group_scope(self) -> frozenset[uuid.UUID] | None:
        if self.machine_group_ids is None:
            return None
        return frozenset(uuid.UUID(value) for value in self.machine_group_ids)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"ApiToken(id={self.id!r}, name={self.name!r})"


# Imported last, and only for type checking: every class above is already
# defined by the time this module points back at the models it relates
# to, so no import cycle can leave a class half-defined (CodeQL's
# "Module-level cyclic import"). SQLAlchemy resolves the relationship
# targets by name through its registry, never through these imports.
if TYPE_CHECKING:
    from app.db.models.user import User
