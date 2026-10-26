"""Per-IP rate limiting for the login endpoints, backed by Redis.

This is deliberately separate from the existing per-*account* lockout in
`app.auth.login` (`User.failed_login_attempts`/`locked_until`): that one
protects a single account from being guessed, but has no limit on how many
*different* usernames one source can try. This closes that gap with a
coarse, high-limit-by-design per-IP cap — meant to blunt obviously abusive
volume (credential stuffing, username enumeration at scale), not to
inconvenience a legitimate user who mistypes a password a few times or a
shared office/VPN egress IP with several people logging in.

Uses `app.state.redis` — a plain `redis.asyncio.Redis` pool opened once in
`app.main`'s lifespan, so a burst of login attempts doesn't open a fresh
connection per request. It hits the same Redis *server* the Celery queue
uses, but shares nothing else with it: this is straight `INCR`/`EXPIRE`, no
queue involvement whatsoever.
"""

from __future__ import annotations

from typing import Protocol


class _RedisLike(Protocol):
    async def incr(self, key: str) -> int:
        """Redis INCR."""

    async def expire(self, key: str, seconds: int, *, nx: bool = False) -> object:
        """Redis EXPIRE (`nx`: only when the key has no TTL yet)."""


async def check_rate_limit(
    redis: _RedisLike, key: str, *, limit: int, window_seconds: int
) -> bool:
    """Increment `key`'s counter and return whether it's still within `limit`.

    A fixed-window counter, not a true sliding window — good enough for
    "stop obviously abusive volume" and much cheaper than a sorted-set
    sliding window. The window's TTL is set by the first increment of a
    window; every later one re-applies it with `EXPIRE ... NX`, which only
    acts when the key has no TTL. Without that, a crash or dropped
    connection between the first `INCR` and its `EXPIRE` would leave a
    counter that never expires — locking that source out of the login
    page for good once it reached the limit.
    """
    current = await redis.incr(key)
    if current == 1:
        await redis.expire(key, window_seconds)
    else:
        await redis.expire(key, window_seconds, nx=True)
    return current <= limit
