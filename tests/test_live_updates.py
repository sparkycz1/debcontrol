"""app/services/live_updates.py (the Redis pub/sub "something changed, go
check" doorbell) and the jobs in app/tasks/jobs.py that ring it.

No real Redis is touched: `aioredis.from_url` is monkeypatched to a fake
client that just records what would have been published — same "no real
infrastructure in tests" rule this suite already follows for Celery/Redis
elsewhere (see tests/conftest.py's module comment). The WebSocket relay
itself (app/web/routes/live_ws.py) has no dedicated test here, for the
same reason app/web/routes/terminal_ws.py doesn't either: this project's
async test client (httpx + ASGITransport) has no WebSocket support, so
that module is exercised for real only by running the app.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.tasks.jobs as jobs
from app.db.models.machine import AuthMethod, Machine
from app.services import live_updates


class _FakePublishedRedis:
    def __init__(self, sink: list[tuple[str, str]]) -> None:
        self._sink = sink

    async def publish(self, channel: str, message: str) -> None:
        self._sink.append((channel, message))

    async def aclose(self) -> None:
        return None


class _FakeAioredisModule:
    """Stands in for the whole `redis.asyncio` module (imported in
    live_updates.py as `aioredis`) — swapping the binding wholesale rather
    than patching `.from_url` on the real, shared module object."""

    def __init__(self, sink: list[tuple[str, str]]) -> None:
        self._sink = sink

    def from_url(self, *args: object, **kwargs: object) -> _FakePublishedRedis:
        return _FakePublishedRedis(self._sink)


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Every (channel, message) `publish_machine_event` would have sent."""
    sink: list[tuple[str, str]] = []
    monkeypatch.setattr(live_updates, "aioredis", _FakeAioredisModule(sink))
    return sink


def test_channel_for_is_namespaced_per_machine():
    assert live_updates.channel_for("abc") == "debcontrol:live:machine:abc"
    assert live_updates.channel_for("abc") != live_updates.channel_for("def")


async def test_publish_machine_event_sends_the_kind_as_json(published):
    await live_updates.publish_machine_event("m1", live_updates.KIND_FACTS)

    assert len(published) == 1
    channel, message = published[0]
    assert channel == "debcontrol:live:machine:m1"
    assert json.loads(message) == {"kind": "facts"}


class _BoomingAioredisModule:
    def from_url(self, *args: object, **kwargs: object) -> _FakePublishedRedis:
        raise ConnectionError("no redis here")


async def test_publish_machine_event_is_best_effort_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broken Redis connection must never raise out of this — see the
    module docstring's reasoning: a missed push just means the polling
    fallback catches it a little later."""
    monkeypatch.setattr(live_updates, "aioredis", _BoomingAioredisModule())

    await live_updates.publish_machine_event("m1", live_updates.KIND_STATUS)  # must not raise


async def _make_machine(db_session_factory: async_sessionmaker[AsyncSession]) -> uuid.UUID:
    async with db_session_factory() as session:
        machine = Machine(
            name="live-updates-target",
            ip_address="10.7.7.7",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            secret_encrypted=None,
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        session.add(machine)
        await session.commit()
        return machine.id


async def test_refresh_facts_publishes_a_facts_event(
    db_session_factory, monkeypatch, published
):
    machine_id = await _make_machine(db_session_factory)
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    async def _fake_gather_facts(
        machine: Machine, secret: object, connect_timeout: float
    ) -> dict[str, object]:
        return {
            "hostname": "h",
            "os_version": "Debian 13",
            "os_id": "debian",
            "kernel_version": "6.1",
            "cpu_architecture": "x86_64",
            "cpu_cores": 4,
            "cpu_model": "Some CPU",
            "ram_bytes": 1000,
            "ram_speed_mhz": None,
            "disks": [],
            "reboot_required": False,
            "uptime_seconds": 10,
            "process_count": 5,
            "filesystems": [],
            "network_interfaces": [],
        }

    monkeypatch.setattr(jobs, "gather_facts", _fake_gather_facts)

    result = await jobs._refresh_machine_facts(str(machine_id))

    assert result["ok"] is True
    assert [json.loads(m)["kind"] for _c, m in published] == ["facts"]


async def test_ping_all_machines_publishes_a_status_event_per_checked_machine(
    db_session_factory, monkeypatch, published
):
    machine_id = await _make_machine(db_session_factory)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        # Never checked yet — always due, regardless of the configured interval.
        machine.last_ping_at = None
        await session.commit()

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    async def _fake_check_reachable(ip_address: str, port: int) -> bool:
        return True

    monkeypatch.setattr(jobs, "check_reachable", _fake_check_reachable)

    await jobs._ping_all_machines()

    assert [json.loads(m)["kind"] for _c, m in published] == ["status"]
