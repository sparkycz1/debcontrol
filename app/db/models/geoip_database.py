"""The downloaded GeoIP database itself — a separate singleton table from
`AppSettings`, not a column on it. `AppSettings` is read on essentially
every request; a multi-megabyte `.mmdb` blob living there would be a cost
every single caller pays, even ones that never touch GeoIP. See
`app.services.geoip` for how this is downloaded, cached, and read.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import LargeBinary, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

SINGLETON_ID = 1


class GeoipDatabase(Base):
    __tablename__ = "geoip_database"

    id: Mapped[int] = mapped_column(primary_key=True)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"GeoipDatabase(id={self.id!r}, updated_at={self.updated_at!r})"
