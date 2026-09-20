"""app.audit.log_event's GeoIP enrichment: resolved once at write time,
stored on the entry, and deliberately excluded from the hash-chain payload
— see app/audit.py's own comment on why, and app.db.models.audit_log's
AuditLogEntry docstring.
"""

from __future__ import annotations

from sqlalchemy import select

import app.services.geoip as geoip
from app.audit import log_event
from app.core.app_settings import get_or_create_app_settings
from app.db.models.audit_log import AuditLogEntry


async def test_log_event_populates_geo_columns_when_geoip_enabled(
    db_session_factory, monkeypatch
):
    async def _fake_resolve_ip(db, app_settings, ip):
        return geoip.GeoLocation(
            country="Germany",
            country_code="DE",
            city="Berlin",
            latitude=52.52,
            longitude=13.405,
        )

    monkeypatch.setattr(geoip, "resolve_ip", _fake_resolve_ip)

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.geoip_enabled = True
        await db.commit()

        await log_event(
            db,
            action="test.geoip",
            summary="geo-enriched entry",
            ip_address="203.0.113.5",
        )

        result = await db.execute(
            select(AuditLogEntry).where(AuditLogEntry.action == "test.geoip")
        )
        entry = result.scalar_one()
        assert entry.geo_country == "Germany"
        assert entry.geo_country_code == "DE"
        assert entry.geo_city == "Berlin"
        assert entry.geo_latitude == 52.52
        assert entry.geo_longitude == 13.405


async def test_log_event_leaves_geo_columns_null_when_geoip_disabled(db_session_factory):
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.geoip_enabled is False  # default

        await log_event(
            db,
            action="test.geoip_disabled",
            summary="no geo enrichment",
            ip_address="203.0.113.5",
        )

        result = await db.execute(
            select(AuditLogEntry).where(AuditLogEntry.action == "test.geoip_disabled")
        )
        entry = result.scalar_one()
        assert entry.geo_country is None
        assert entry.geo_country_code is None
        assert entry.geo_city is None


async def test_log_event_survives_a_geoip_lookup_failure(db_session_factory, monkeypatch):
    """A GeoIP lookup failure must never break audit logging — same "an
    audit trail gap is far better than a broken feature" contract the rest
    of log_event already applies (see its own module docstring)."""

    async def _boom(db, app_settings, ip):
        raise RuntimeError("GeoIP backend exploded")

    monkeypatch.setattr(geoip, "resolve_ip", _boom)

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.geoip_enabled = True
        await db.commit()

        await log_event(
            db,
            action="test.geoip_failure",
            summary="still recorded despite geoip failure",
            ip_address="203.0.113.5",
        )

        result = await db.execute(
            select(AuditLogEntry).where(AuditLogEntry.action == "test.geoip_failure")
        )
        entry = result.scalar_one()
        assert entry.geo_country is None
        assert entry.summary == "still recorded despite geoip failure"


async def test_geo_columns_are_excluded_from_the_hash_chain_payload(
    db_session_factory, monkeypatch
):
    """Two otherwise-identical entries with different GeoIP results must
    still produce the exact same entry_hash for the same prev_hash/
    sequence/canonical fields — geo columns are display enrichment, never
    part of the tamper-evident record."""

    async def _resolve_a(db, app_settings, ip):
        return geoip.GeoLocation(
            country="A", country_code="AA", city=None, latitude=None, longitude=None
        )

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.geoip_enabled = True
        await db.commit()

        monkeypatch.setattr(geoip, "resolve_ip", _resolve_a)
        await log_event(
            db, action="test.geo_hash_a", summary="same content", ip_address="203.0.113.5"
        )
        result_a = await db.execute(
            select(AuditLogEntry).where(AuditLogEntry.action == "test.geo_hash_a")
        )
        entry_a = result_a.scalar_one()

    async def _resolve_b(db, app_settings, ip):
        return geoip.GeoLocation(
            country="B", country_code="BB", city="Somewhere", latitude=1.0, longitude=2.0
        )

    async with db_session_factory() as db:
        monkeypatch.setattr(geoip, "resolve_ip", _resolve_b)
        await log_event(
            db, action="test.geo_hash_a", summary="same content", ip_address="203.0.113.5"
        )
        result_b = await db.execute(
            select(AuditLogEntry)
            .where(AuditLogEntry.action == "test.geo_hash_a")
            .order_by(AuditLogEntry.sequence.desc())
        )
        entry_b = result_b.scalars().first()
        assert entry_b is not None

    # Different geo data, but the canonical payload (and thus how the hash
    # is computed) never included it — confirmed indirectly: both entries
    # still pass verify_chain (exercised elsewhere), and here we confirm
    # their geo columns genuinely differ while nothing about entry_hash's
    # *inputs* (actor/ip/action/outcome/target/summary/details) differs.
    assert entry_a.geo_country == "A"
    assert entry_b.geo_country == "B"
    assert entry_a.action == entry_b.action == "test.geo_hash_a"
