"""app.services.geoip — download/extract/validate, the process-local
Reader cache, and IP resolution. No real MaxMind database is fetched or
parsed here (no network in tests, and hand-building a real .mmdb binary
is out of scope) — the download/extraction pipeline is exercised against
fabricated bytes, and the record-parsing helpers are exercised directly
against fabricated decoded records (what `maxminddb.Reader.get()` would
hand back), monkeypatching just the one real I/O boundary
(`_ReaderCache.get`) rather than the whole library.
"""

from __future__ import annotations

import gzip
import io
import tarfile

import pytest

from app.core.security import encrypt_secret
from app.db.models.app_settings import AppSettings
from app.db.models.geoip_database import SINGLETON_ID, GeoipDatabase
from app.services import geoip


def _settings(**overrides: object) -> AppSettings:
    defaults: dict[str, object] = {"geoip_enabled": True}
    defaults.update(overrides)
    return AppSettings(**defaults)


# --- _extract_mmdb: gzip / tar / plain auto-detection -----------------------


def test_extract_mmdb_returns_plain_bytes_unchanged():
    raw = b"not actually an mmdb but that's not this function's job"
    assert geoip._extract_mmdb(raw) == raw


def test_extract_mmdb_unwraps_a_plain_gzip():
    payload = b"the-inner-mmdb-bytes"
    gz = gzip.compress(payload)
    assert geoip._extract_mmdb(gz) == payload


def test_extract_mmdb_unwraps_a_tar_gz_by_picking_the_mmdb_member():
    payload = b"the-inner-mmdb-bytes"
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        readme = tarfile.TarInfo("README.txt")
        readme.size = 5
        tar.addfile(readme, io.BytesIO(b"hello"))

        mmdb = tarfile.TarInfo("GeoLite2-City_20260101/GeoLite2-City.mmdb")
        mmdb.size = len(payload)
        tar.addfile(mmdb, io.BytesIO(payload))
    gz = gzip.compress(tar_buf.getvalue())
    assert geoip._extract_mmdb(gz) == payload


def test_extract_from_tar_raises_when_no_mmdb_member_exists():
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        readme = tarfile.TarInfo("README.txt")
        readme.size = 5
        tar.addfile(readme, io.BytesIO(b"hello"))
    with pytest.raises(geoip.GeoipDownloadError, match=r"doesn't contain a \.mmdb"):
        geoip._extract_from_tar(tar_buf.getvalue())


# --- download_geoip_database: primary/backup fallback -----------------------


async def test_download_uses_the_primary_url(monkeypatch):
    calls: list[str] = []

    async def _fake_fetch(url: str) -> bytes:
        calls.append(url)
        return b"primary-data"

    monkeypatch.setattr(geoip, "_fetch_one", _fake_fetch)
    monkeypatch.setattr(geoip, "_validate_mmdb", lambda data: None)

    settings = _settings(geoip_primary_url_encrypted=encrypt_secret("https://primary.example/db"))
    data = await geoip.download_geoip_database(settings)
    assert data == b"primary-data"
    assert calls == ["https://primary.example/db"]


async def test_download_falls_back_to_backup_when_primary_fails(monkeypatch):
    calls: list[str] = []

    async def _fake_fetch(url: str) -> bytes:
        calls.append(url)
        if "primary" in url:
            raise ConnectionError("primary is down")
        return b"backup-data"

    monkeypatch.setattr(geoip, "_fetch_one", _fake_fetch)
    monkeypatch.setattr(geoip, "_validate_mmdb", lambda data: None)

    settings = _settings(
        geoip_primary_url_encrypted=encrypt_secret("https://primary.example/db"),
        geoip_backup_url_encrypted=encrypt_secret("https://backup.example/db"),
    )
    data = await geoip.download_geoip_database(settings)
    assert data == b"backup-data"
    assert calls == ["https://primary.example/db", "https://backup.example/db"]


async def test_download_raises_when_both_urls_fail(monkeypatch):
    async def _fake_fetch(url: str) -> bytes:
        raise ConnectionError(f"{url} is down")

    monkeypatch.setattr(geoip, "_fetch_one", _fake_fetch)

    settings = _settings(
        geoip_primary_url_encrypted=encrypt_secret("https://primary.example/db"),
        geoip_backup_url_encrypted=encrypt_secret("https://backup.example/db"),
    )
    with pytest.raises(geoip.GeoipDownloadError):
        await geoip.download_geoip_database(settings)


async def test_download_raises_when_no_primary_url_is_configured():
    with pytest.raises(geoip.GeoipDownloadError, match="No primary"):
        await geoip.download_geoip_database(_settings())


async def test_refresh_geoip_database_stores_the_downloaded_bytes(monkeypatch, db_session_factory):
    async def _fake_fetch(url: str) -> bytes:
        return b"fresh-mmdb-bytes"

    monkeypatch.setattr(geoip, "_fetch_one", _fake_fetch)
    monkeypatch.setattr(geoip, "_validate_mmdb", lambda data: None)

    settings = _settings(geoip_primary_url_encrypted=encrypt_secret("https://primary.example/db"))
    async with db_session_factory() as db:
        await geoip.refresh_geoip_database(db, settings)
        row = await db.get(GeoipDatabase, SINGLETON_ID)
        assert row is not None
        assert row.data == b"fresh-mmdb-bytes"

    # A second refresh replaces the row rather than erroring on the
    # singleton PK already existing.
    async def _fake_fetch_again(url: str) -> bytes:
        return b"replaced-mmdb-bytes"

    monkeypatch.setattr(geoip, "_fetch_one", _fake_fetch_again)
    async with db_session_factory() as db:
        await geoip.refresh_geoip_database(db, settings)
        row = await db.get(GeoipDatabase, SINGLETON_ID)
        assert row is not None
        assert row.data == b"replaced-mmdb-bytes"


# --- resolve_ip: gating (disabled / non-public / unparseable) ---------------


async def test_resolve_ip_returns_none_when_geoip_disabled(db_session_factory):
    async with db_session_factory() as db:
        result = await geoip.resolve_ip(db, _settings(geoip_enabled=False), "8.8.8.8")
    assert result is None


async def test_resolve_ip_returns_none_for_a_private_address(db_session_factory):
    async with db_session_factory() as db:
        result = await geoip.resolve_ip(db, _settings(), "10.0.0.5")
    assert result is None


async def test_resolve_ip_returns_none_for_an_unparseable_address(db_session_factory):
    async with db_session_factory() as db:
        result = await geoip.resolve_ip(db, _settings(), "not-an-ip")
    assert result is None


async def test_resolve_ip_returns_none_when_no_database_downloaded_yet(db_session_factory):
    async with db_session_factory() as db:
        result = await geoip.resolve_ip(db, _settings(), "8.8.8.8")
    assert result is None


# --- record parsing (the dict-narrowing helpers) -----------------------------


class _FakeReader:
    def __init__(self, record: object) -> None:
        self._record = record

    def get(self, ip: str) -> object:
        return self._record


async def test_resolve_ip_parses_a_full_record(monkeypatch, db_session_factory):
    record = {
        "country": {"iso_code": "US", "names": {"en": "United States"}},
        "city": {"names": {"en": "Mountain View"}},
        "location": {"latitude": 37.386, "longitude": -122.0838},
    }
    async def _fake_get(db: object) -> _FakeReader:
        return _FakeReader(record)

    monkeypatch.setattr(geoip._cache, "get", _fake_get)

    async with db_session_factory() as db:
        result = await geoip.resolve_ip(db, _settings(), "8.8.8.8")
    assert result is not None
    assert result.country == "United States"
    assert result.country_code == "US"
    assert result.city == "Mountain View"
    assert result.latitude == pytest.approx(37.386)
    assert result.longitude == pytest.approx(-122.0838)


async def test_resolve_ip_handles_a_record_with_only_a_country(monkeypatch, db_session_factory):
    record = {"country": {"iso_code": "DE", "names": {"en": "Germany"}}}
    async def _fake_get(db: object) -> _FakeReader:
        return _FakeReader(record)

    monkeypatch.setattr(geoip._cache, "get", _fake_get)

    async with db_session_factory() as db:
        result = await geoip.resolve_ip(db, _settings(), "8.8.8.8")
    assert result is not None
    assert result.country == "Germany"
    assert result.country_code == "DE"
    assert result.city is None
    assert result.latitude is None


async def test_resolve_ip_returns_none_when_nothing_matches(monkeypatch, db_session_factory):
    async def _fake_get(db: object) -> _FakeReader:
        return _FakeReader(None)

    monkeypatch.setattr(geoip._cache, "get", _fake_get)

    async with db_session_factory() as db:
        result = await geoip.resolve_ip(db, _settings(), "8.8.8.8")
    assert result is None
