"""GeoIP lookups — resolves a public IP address to a country/city/lat-long,
looked up once at audit-log write time (`app.audit.log_event`) from a
MaxMind-DB-format (`.mmdb`) database this app downloads itself and caches
in `GeoipDatabase`.

Never bundled — MaxMind's GeoLite2 license forbids redistribution. Deploy-
time config only decides *whether* GeoIP is on and *where* to download the
database from (Settings → Security → GeoIP); the actual downloaded bytes
live in the database (`GeoipDatabase`, a separate singleton table from
`AppSettings` — see that model's own docstring for why).

Deliberately only ever for a public IP — a machine's own LAN address, or a
login coming through an internal reverse proxy, has no real-world location
and is never looked up (`ipaddress.ip_address(...).is_global` gates every
lookup, same guard `app.core.proxy_headers` already applies elsewhere for
a similar "is this address trustworthy/meaningful" question).
"""

from __future__ import annotations

import gzip
import io
import logging
import tarfile
import time
from dataclasses import dataclass
from ipaddress import ip_address as parse_ip
from typing import Any

import httpx
import maxminddb
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import decrypt_secret
from app.db.models.app_settings import AppSettings
from app.db.models.geoip_database import SINGLETON_ID, GeoipDatabase

logger = logging.getLogger(__name__)

_DOWNLOAD_TIMEOUT_SECONDS = 30.0
# How long an in-process Reader is trusted before re-checking whether
# `GeoipDatabase.updated_at` has moved on — the overwhelming majority of
# calls (every audit-log write) cost one wall-clock comparison, not a DB
# round trip. Doesn't need to be anywhere near real-time: a newly-refreshed
# database (at most weekly, see `DEFAULT_GEOIP_REFRESH_INTERVAL_HOURS`)
# taking up to an hour to actually apply everywhere is a non-issue.
_READER_REVALIDATE_SECONDS = 3600
_CACHE_FILENAME = "geoip.mmdb"


@dataclass(frozen=True, slots=True)
class GeoLocation:
    country: str | None
    country_code: str | None
    city: str | None
    latitude: float | None
    longitude: float | None


class GeoipDownloadError(Exception):
    """Neither the primary nor the backup URL produced a usable database."""


def _looks_like_tar(data: bytes) -> bool:
    try:
        with tarfile.open(fileobj=io.BytesIO(data)):
            return True
    except tarfile.TarError:
        return False


def _extract_from_tar(data: bytes) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        for member in tar.getmembers():
            if member.name.endswith(".mmdb"):
                extracted = tar.extractfile(member)
                if extracted is not None:
                    return extracted.read()
    raise GeoipDownloadError("Downloaded archive doesn't contain a .mmdb file.")


def _extract_mmdb(raw: bytes) -> bytes:
    """MaxMind distributes GeoLite2 as a plain `.mmdb`, a `.mmdb.gz`, or a
    `.tar.gz` containing one — auto-detect and unwrap either."""
    if raw[:2] == b"\x1f\x8b":  # gzip magic number
        decompressed = gzip.decompress(raw)
        return _extract_from_tar(decompressed) if _looks_like_tar(decompressed) else decompressed
    if _looks_like_tar(raw):
        return _extract_from_tar(raw)
    return raw


def _validate_mmdb(data: bytes) -> None:
    """Raises if `data` isn't a readable MaxMind DB — checked before it's
    ever stored, so a bad URL/expired license key fails loudly at download
    time instead of silently breaking every future lookup."""
    with maxminddb.open_database(io.BytesIO(data)):
        pass


async def _fetch_one(url: str) -> bytes:
    async with httpx.AsyncClient(
        timeout=_DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=True
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
        return _extract_mmdb(response.content)


def _describe_error(exc: Exception) -> str:
    """A short, safe-to-log description of `exc` that never includes the
    configured download URL — a MaxMind "permalink" embeds a license key
    in its query string, and `httpx.HTTPStatusError`/`ConnectError`/etc.
    all put the full request URL straight into their own `str()`. This
    description is what ends up in the application log, the audit log
    (`app.tasks.jobs._refresh_geoip_database`, readable by anyone with
    `audit.view`, not just `settings.manage`), and the Settings page's own
    error banner — none of which should ever leak a secret embedded in an
    admin-entered URL."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, httpx.TimeoutException):
        return "timed out"
    if isinstance(exc, httpx.HTTPError):
        return f"{type(exc).__name__} (network error)"
    return f"{type(exc).__name__}: could not parse the downloaded file"


async def download_geoip_database(app_settings: AppSettings) -> bytes:
    """Downloads and validates the configured GeoIP database — the primary
    URL first, falling back to the backup only on outright failure
    (network error, bad status, unparseable file), never merely because
    the primary is stale-but-working."""
    primary = (
        decrypt_secret(app_settings.geoip_primary_url_encrypted)
        if app_settings.geoip_primary_url_encrypted
        else None
    )
    backup = (
        decrypt_secret(app_settings.geoip_backup_url_encrypted)
        if app_settings.geoip_backup_url_encrypted
        else None
    )
    if not primary:
        raise GeoipDownloadError("No primary GeoIP database URL is configured.")

    last_description: str | None = None
    last_error: Exception | None = None
    for label, url in (("primary", primary), ("backup", backup)):
        if not url:
            continue
        try:
            data = await _fetch_one(url)
            _validate_mmdb(data)
        except Exception as exc:
            last_description = _describe_error(exc)
            last_error = exc
            logger.warning("GeoIP %s database download failed: %s", label, last_description)
        else:
            return data
    raise GeoipDownloadError(
        f"Both GeoIP database URLs failed ({last_description})"
    ) from last_error


async def refresh_geoip_database(db: AsyncSession, app_settings: AppSettings) -> None:
    """Downloads the configured database and stores it, replacing whatever
    was there before. Raises `GeoipDownloadError` on failure — callers
    (the Settings "Download now" button, the periodic Celery task) decide
    how to surface that."""
    data = await download_geoip_database(app_settings)
    result = await db.execute(select(GeoipDatabase).where(GeoipDatabase.id == SINGLETON_ID))
    row = result.scalar_one_or_none()
    if row is None:
        row = GeoipDatabase(id=SINGLETON_ID, data=data)
        db.add(row)
    else:
        row.data = data
    await db.commit()


class _ReaderCache:
    """Process-local cache of the parsed `.mmdb` Reader — one per worker
    process, revalidated at most every `_READER_REVALIDATE_SECONDS` against
    `GeoipDatabase.updated_at` rather than re-read on every single lookup."""

    def __init__(self) -> None:
        self._reader: maxminddb.Reader | None = None
        self._loaded_updated_at: object = None
        self._last_checked_monotonic: float = 0.0

    async def get(self, db: AsyncSession) -> maxminddb.Reader | None:
        now = time.monotonic()
        if self._reader is not None and (now - self._last_checked_monotonic) < (
            _READER_REVALIDATE_SECONDS
        ):
            return self._reader

        result = await db.execute(select(GeoipDatabase).where(GeoipDatabase.id == SINGLETON_ID))
        row = result.scalar_one_or_none()
        self._last_checked_monotonic = now
        if row is None:
            self._reader = None
            self._loaded_updated_at = None
            return None

        if self._reader is not None and row.updated_at == self._loaded_updated_at:
            return self._reader

        cache_path = get_settings().ssh_data_dir / _CACHE_FILENAME
        cache_path.write_bytes(row.data)
        if self._reader is not None:
            self._reader.close()
        self._reader = maxminddb.open_database(cache_path)
        self._loaded_updated_at = row.updated_at
        return self._reader


_cache = _ReaderCache()


async def resolve_ip(
    db: AsyncSession, app_settings: AppSettings, ip: str | None
) -> GeoLocation | None:
    """Resolves `ip` to a `GeoLocation`, or `None` if GeoIP is disabled, no
    database has been downloaded yet, the address isn't public, or nothing
    in the database matches it."""
    if not app_settings.geoip_enabled or not ip:
        return None
    try:
        parsed = parse_ip(ip)
    except ValueError:
        return None
    if not parsed.is_global:
        return None

    reader = await _cache.get(db)
    if reader is None:
        return None

    try:
        record = reader.get(ip)
    except Exception:
        logger.warning("GeoIP lookup failed for an address", exc_info=True)
        return None
    if not isinstance(record, dict):
        return None

    country = _sub_dict(record, "country")
    city = _sub_dict(record, "city")
    location = _sub_dict(record, "location")
    country_names = _sub_dict(country, "names")
    city_names = _sub_dict(city, "names")
    return GeoLocation(
        country=_as_str(country_names.get("en")),
        country_code=_as_str(country.get("iso_code")),
        city=_as_str(city_names.get("en")),
        latitude=_as_float(location.get("latitude")),
        longitude=_as_float(location.get("longitude")),
    )


def _sub_dict(record: dict[str, Any], key: str) -> dict[str, Any]:
    """The maxminddb library types a decoded record's values as a broad
    `Record` union (str/int/float/list/dict) since the format is generic —
    every field this app actually reads back is known (from GeoLite2's own
    documented schema) to be either a nested dict or absent; this narrows
    that back down explicitly rather than asserting/ignoring the type."""
    value = record.get(key)
    return value if isinstance(value, dict) else {}


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _as_float(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None
