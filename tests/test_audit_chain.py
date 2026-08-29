from __future__ import annotations

from sqlalchemy import select

from app.audit import log_event, verify_chain
from app.db.models.audit_log import AuditLogEntry


async def test_log_event_chains_sequential_entries(db_session_factory):
    async with db_session_factory() as session:
        await log_event(session, action="test.one", summary="first")
        await log_event(session, action="test.two", summary="second")
        await log_event(session, action="test.three", summary="third")

    async with db_session_factory() as session:
        result = await session.execute(select(AuditLogEntry).order_by(AuditLogEntry.sequence))
        entries = list(result.scalars().all())

    assert [e.sequence for e in entries] == [1, 2, 3]
    assert entries[0].prev_hash is None
    assert entries[1].prev_hash == entries[0].entry_hash
    assert entries[2].prev_hash == entries[1].entry_hash
    # Every hash is populated and distinct.
    hashes = {e.entry_hash for e in entries}
    assert len(hashes) == 3
    assert all(h and len(h) == 64 for h in hashes)


async def test_verify_chain_empty_log_is_ok(db_session_factory):
    async with db_session_factory() as session:
        result = await verify_chain(session)

    assert result.ok is True
    assert result.checked == 0


async def test_verify_chain_ok_on_untampered_log(db_session_factory):
    async with db_session_factory() as session:
        await log_event(session, action="test.one", summary="first")
        await log_event(session, action="test.two", summary="second")

    async with db_session_factory() as session:
        result = await verify_chain(session)

    assert result.ok is True
    assert result.checked == 2


async def test_verify_chain_detects_altered_entry_content(db_session_factory):
    async with db_session_factory() as session:
        await log_event(session, action="test.one", summary="first")
        await log_event(session, action="test.two", summary="second")

    async with db_session_factory() as session:
        result = await session.execute(select(AuditLogEntry).where(AuditLogEntry.sequence == 1))
        entry = result.scalar_one()
        entry.summary = "tampered!"
        await session.commit()

    async with db_session_factory() as session:
        result = await verify_chain(session)

    assert result.ok is False
    assert result.broken_at_sequence == 1


async def test_verify_chain_detects_deleted_most_recent_entry(db_session_factory):
    async with db_session_factory() as session:
        await log_event(session, action="test.one", summary="first")
        await log_event(session, action="test.two", summary="second")

    async with db_session_factory() as session:
        result = await session.execute(select(AuditLogEntry).where(AuditLogEntry.sequence == 2))
        entry = result.scalar_one()
        await session.delete(entry)
        await session.commit()

    async with db_session_factory() as session:
        result = await verify_chain(session)

    # Entry #1 alone is internally consistent, but its hash no longer
    # matches the chain's recorded tip — the deletion is still caught.
    assert result.ok is False
    assert "tip" in result.message


async def test_verify_chain_detects_gap_from_deleted_middle_entry(db_session_factory):
    async with db_session_factory() as session:
        await log_event(session, action="test.one", summary="first")
        await log_event(session, action="test.two", summary="second")
        await log_event(session, action="test.three", summary="third")

    async with db_session_factory() as session:
        result = await session.execute(select(AuditLogEntry).where(AuditLogEntry.sequence == 2))
        entry = result.scalar_one()
        await session.delete(entry)
        await session.commit()

    async with db_session_factory() as session:
        result = await verify_chain(session)

    assert result.ok is False
    assert result.broken_at_sequence == 2
