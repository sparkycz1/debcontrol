"""`app.auth.rate_limit.check_rate_limit`: the per-IP login limiter."""

from __future__ import annotations

from app.auth.rate_limit import check_rate_limit
from tests.conftest import FakeRedis


async def test_counts_up_to_the_limit_then_refuses() -> None:
    redis = FakeRedis()
    results = [
        await check_rate_limit(redis, "login:1.2.3.4", limit=3, window_seconds=60)
        for _ in range(4)
    ]
    assert results == [True, True, True, False]


async def test_every_increment_makes_sure_the_window_expires() -> None:
    # The first increment sets the window; every later one re-applies it
    # only if missing (NX), so a lost EXPIRE can't leave a counter that
    # never resets and locks one address out of the login page for good.
    redis = FakeRedis()
    for _ in range(3):
        await check_rate_limit(redis, "k", limit=10, window_seconds=60)
    assert redis.expire_calls == [("k", 60, False), ("k", 60, True), ("k", 60, True)]
