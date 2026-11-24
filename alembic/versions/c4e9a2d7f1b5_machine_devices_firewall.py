"""Hardware devices, IPMI, UPS, firewall and Fail2Ban on the machine

Six new nullable JSON columns on `machines`, filled by the next facts
refresh (`pci_devices`, `usb_devices`, `ipmi`, `firewall`, `fail2ban`) and
the next monitoring sample (`ups_devices`). Nothing existing changes.

Revision ID: c4e9a2d7f1b5
Revises: b8e2f4a6c1d3
Create Date: 2026-11-24 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c4e9a2d7f1b5"
down_revision: str | None = "b8e2f4a6c1d3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLUMNS = ("pci_devices", "usb_devices", "ipmi", "firewall", "fail2ban", "ups_devices")


def upgrade() -> None:
    with op.batch_alter_table("machines") as batch:
        for name in _COLUMNS:
            batch.add_column(sa.Column(name, sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("machines") as batch:
        for name in reversed(_COLUMNS):
            batch.drop_column(name)
