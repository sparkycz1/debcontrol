"""Redact webhook URLs already stored in the notification delivery history

Revision ID: b5d7f9a1c3e6
Revises: a4c6e8f0b2d4
Create Date: 2026-09-27

A webhook/ntfy/Discord/Gotify URL's path is its secret, but up to 0.79.0
the delivery history (`notification_logs.target`, and an error message
that happened to echo the URL) stored it verbatim — readable by anyone
with `notification.view`. New rows are redacted at write time
(`app.services.push_channels.redact_url`); this scrubs the existing ones
the same way. Data only, no schema change; not reversible (the point).
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlsplit

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b5d7f9a1c3e6"
down_revision: str | None = "a4c6e8f0b2d4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def _redact(url: str) -> str:
    # A frozen copy of `push_channels.redact_url` — a migration must not
    # change behaviour when the app code it would import does.
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return "…"
    host = parts.hostname + (f":{parts.port}" if parts.port else "")
    rest = "/…" if parts.path.strip("/") or parts.query else ""
    return f"{parts.scheme}://{host}{rest}"


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT id, target, error FROM notification_logs "
            "WHERE target LIKE 'http://%' OR target LIKE 'https://%'"
        )
    ).fetchall()
    for row_id, target, error in rows:
        redacted = _redact(target)
        if redacted == target:
            continue
        bind.execute(
            sa.text("UPDATE notification_logs SET target = :target, error = :error WHERE id = :id"),
            {
                "id": row_id,
                "target": redacted,
                "error": error.replace(target, redacted) if error else error,
            },
        )


def downgrade() -> None:
    # The original URLs are gone on purpose.
    pass
