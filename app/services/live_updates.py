"""Something-changed-go-check push notifications over Redis pub/sub —
what makes a machine's Overview/Monitoring/Updates tabs update the moment a
background job finishes, instead of waiting out their htmx polling
interval (see `app/web/routes/live_ws.py`, the WebSocket that relays these
to the browser, and `app/web/static/js/live-updates.js`, the client that
turns one into an htmx re-fetch of the matching panel).

Deliberately minimal: a published message carries only a `kind` — never
machine data. A client that receives one just re-triggers the matching
htmx panel's own `hx-get` (still permission/scope-checked exactly like its
periodic poll already was); this channel is a doorbell, not a data feed,
so there's nothing sensitive in it and no risk of a push payload drifting
out of sync with what a fresh fetch would show.

Called from two different worlds: the FastAPI process (which has a
long-lived `app.state.redis`) and Celery worker processes (separate OS
processes entirely, each running these jobs' `asyncio.run(...)` wrapper —
see `app.tasks.jobs`'s module docstring). Rather than plumb `app.state`
through to worker code that has no `app` object, this opens its own
short-lived Redis connection per publish. That's more round trips than
reusing a shared connection, but publishes happen at most a few times per
job (not per SSH byte), and it keeps this module usable from anywhere
without a FastAPI request/app in scope.
"""

from __future__ import annotations

import json
import logging

import redis.asyncio as aioredis

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_CHANNEL_PREFIX = "debcontrol:live:machine:"
# One channel for the whole fleet — what the machine list listens on. It
# carries only a `kind`, never which machine changed (so it can't reveal a
# machine outside the viewer's scope), and only the changes the list shows:
# update availability, and reachability when it actually flips — not every
# reachability tick, which would redraw the list every minute for nothing.
FLEET_CHANNEL = "debcontrol:live:fleet"

# The finite set of "something changed" hints a client understands — see
# app/web/static/js/live-updates.js. Keeping this closed (rather than any
# free-form string) means a typo here fails loudly in review, not silently
# as a push nothing on the client ever matches.
Kind = str
KIND_STATUS = "status"
KIND_FACTS = "facts"
KIND_PACKAGES = "packages"
KIND_SERVICES = "services"
KIND_UPDATES = "updates"


def channel_for(machine_id: str) -> str:
    return f"{_CHANNEL_PREFIX}{machine_id}"


async def _publish(channel: str, kind: Kind) -> None:
    """Best-effort — a failed publish just means the affected panel waits
    for its own polling fallback to catch up a little later. Never worth
    failing (or even slowing down) the actual job over, so every error is
    caught and logged, not raised."""
    try:
        client: aioredis.Redis = aioredis.from_url(  # type: ignore[no-untyped-call]
            get_settings().redis_url
        )
        try:
            await client.publish(channel, json.dumps({"kind": kind}))
        finally:
            await client.aclose()
    except Exception:
        logger.warning("live_updates: failed to publish %r on %s", kind, channel)


async def publish_machine_event(machine_id: str, kind: Kind) -> None:
    """Rings one machine's channel — and, for a change the machine list
    shows (update availability), the fleet channel too."""
    await _publish(channel_for(machine_id), kind)
    if kind == KIND_UPDATES:
        await publish_fleet_event(kind)


async def publish_fleet_event(kind: Kind) -> None:
    """Rings the fleet channel only (see `FLEET_CHANNEL`) — e.g. once per
    reachability sweep in which at least one machine changed state."""
    await _publish(FLEET_CHANNEL, kind)
