"""Push notification services: ntfy, Gotify, Telegram, Discord, Pushover,
and the team chats Mattermost, Slack and Microsoft Teams.

Each is a single HTTPS request with the rule's rendered subject and body —
no extra dependency (Apprise would cover more services, but at the cost of
a large third-party package in the one process that holds every
credential). What each channel needs, stored on the rule
(`NotificationRule`):

| channel  | `webhook_url`                        | token (encrypted)       | recipient        |
|----------|--------------------------------------|-------------------------|------------------|
| ntfy     | topic URL `https://ntfy.sh/mytopic`  | access token (optional) | —                |
| gotify   | server URL `https://gotify.lan`      | application token       | —                |
| telegram | —                                    | bot token               | chat id          |
| discord  | channel webhook URL                  | —                       | —                |
| pushover | —                                    | application API token   | user/group key   |
| mattermost | incoming webhook URL               | —                       | —                |
| slack    | incoming webhook URL                 | —                       | —                |
| teams    | Workflows ("Post to a channel when a webhook request is received") URL | — | — |

Teams takes an Adaptive Card — the format Microsoft's Workflows webhooks
expect (the older Office 365 connector webhooks are being retired and
accept the same message shape).

Like the plain webhook, the URL and token are admin-authored config
(`notification.manage`), not untrusted input. `send(...)` returns
`(status, error)` and never raises — a failing push must never break the
job that triggered it.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.db.models.notification_log import NotificationDeliveryChannel, NotificationDeliveryStatus

C = NotificationDeliveryChannel

CHANNEL_NAMES: dict[str, str] = {
    C.EMAIL.value: "E-mail",
    C.WEBHOOK.value: "Webhook",
    C.NTFY.value: "ntfy",
    C.GOTIFY.value: "Gotify",
    C.TELEGRAM.value: "Telegram",
    C.DISCORD.value: "Discord",
    C.PUSHOVER.value: "Pushover",
    C.MATTERMOST.value: "Mattermost",
    C.SLACK.value: "Slack",
    C.TEAMS.value: "Microsoft Teams",
}
# Channels whose `webhook_url` is required.
URL_CHANNELS = frozenset(
    {
        C.WEBHOOK.value,
        C.NTFY.value,
        C.GOTIFY.value,
        C.DISCORD.value,
        C.MATTERMOST.value,
        C.SLACK.value,
        C.TEAMS.value,
    }
)
# Channels that can't send without a token.
TOKEN_CHANNELS = frozenset({C.GOTIFY.value, C.TELEGRAM.value, C.PUSHOVER.value})
# Channels with an optional token.
OPTIONAL_TOKEN_CHANNELS = frozenset({C.NTFY.value})
RECIPIENT_CHANNELS = frozenset({C.TELEGRAM.value, C.PUSHOVER.value})
PUSH_CHANNELS = frozenset(
    {
        C.NTFY.value,
        C.GOTIFY.value,
        C.TELEGRAM.value,
        C.DISCORD.value,
        C.PUSHOVER.value,
        C.MATTERMOST.value,
        C.SLACK.value,
        C.TEAMS.value,
    }
)

_TIMEOUT_SECONDS = 10
# Each service's own message size limits.
_TELEGRAM_MAX = 4096
_DISCORD_MAX = 2000
_PUSHOVER_TITLE_MAX = 250
_PUSHOVER_MESSAGE_MAX = 1024
_MATTERMOST_MAX = 16383
_SLACK_MAX = 3000  # a section's text limit; plenty for an alert
_TEAMS_MAX = 20000


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _ntfy_request(url: str) -> tuple[str, str]:
    """`https://ntfy.sh/topic` -> (`https://ntfy.sh/`, "topic") — ntfy's
    JSON publishing posts to the server root with the topic in the body,
    which keeps a non-ASCII title intact (HTTP headers can't carry it)."""
    parts = urlsplit(url)
    path = parts.path.rstrip("/")
    base_path, _, topic = path.rpartition("/")
    base = urlunsplit((parts.scheme, parts.netloc, base_path + "/", "", ""))
    return base, topic


def build_request(
    channel: str,
    *,
    url: str | None,
    token: str | None,
    recipient: str | None,
    subject: str,
    body: str,
) -> tuple[str, dict[str, Any]]:
    """`(url, httpx request kwargs)` for one push — pure, so each service's
    exact request shape is testable without a network. Raises ValueError
    when the rule is missing something the channel needs."""
    if channel in URL_CHANNELS and not url:
        raise ValueError(f"No {CHANNEL_NAMES.get(channel, channel)} URL configured.")
    if channel in TOKEN_CHANNELS and not token:
        raise ValueError(f"No {CHANNEL_NAMES.get(channel, channel)} token configured.")
    if channel in RECIPIENT_CHANNELS and not recipient:
        raise ValueError(f"No {CHANNEL_NAMES.get(channel, channel)} recipient configured.")
    if channel == C.NTFY.value:
        assert url is not None
        base, topic = _ntfy_request(url)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return base, {
            "json": {"topic": topic, "title": subject, "message": body},
            "headers": headers,
        }
    if channel == C.GOTIFY.value:
        assert url is not None
        return f"{url.rstrip('/')}/message", {
            "json": {"title": subject, "message": body, "priority": 5},
            "headers": {"X-Gotify-Key": token or ""},
        }
    if channel == C.TELEGRAM.value:
        return f"https://api.telegram.org/bot{token}/sendMessage", {
            "json": {"chat_id": recipient, "text": _clip(f"{subject}\n\n{body}", _TELEGRAM_MAX)}
        }
    if channel == C.DISCORD.value:
        assert url is not None
        return url, {"json": {"content": _clip(f"**{subject}**\n{body}", _DISCORD_MAX)}}
    if channel == C.PUSHOVER.value:
        return "https://api.pushover.net/1/messages.json", {
            "data": {
                "token": token,
                "user": recipient,
                "title": _clip(subject, _PUSHOVER_TITLE_MAX),
                "message": _clip(body, _PUSHOVER_MESSAGE_MAX),
            }
        }
    if channel == C.MATTERMOST.value:
        assert url is not None
        return url, {"json": {"text": _clip(f"**{subject}**\n{body}", _MATTERMOST_MAX)}}
    if channel == C.SLACK.value:
        assert url is not None
        return url, {"json": {"text": _clip(f"*{subject}*\n{body}", _SLACK_MAX)}}
    if channel == C.TEAMS.value:
        assert url is not None
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {"type": "TextBlock", "text": subject, "weight": "Bolder", "wrap": True},
                {"type": "TextBlock", "text": _clip(body, _TEAMS_MAX), "wrap": True},
            ],
        }
        return url, {
            "json": {
                "type": "message",
                "attachments": [
                    {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}
                ],
            }
        }
    raise ValueError(f'"{channel}" is not a push channel.')


async def send(
    channel: str,
    *,
    url: str | None,
    token: str | None,
    recipient: str | None,
    subject: str,
    body: str,
) -> tuple[NotificationDeliveryStatus, str | None]:
    """Deliver one push. Never raises."""
    try:
        target, kwargs = build_request(
            channel, url=url, token=token, recipient=recipient, subject=subject, body=body
        )
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(target, **kwargs)
        if response.status_code >= 400:
            return NotificationDeliveryStatus.FAILED, f"HTTP {response.status_code}"
        return NotificationDeliveryStatus.SENT, None
    except Exception as exc:
        # Never echo a URL back into the log — Telegram's carries the token.
        message = str(exc).replace(token, "***") if token else str(exc)
        if url:
            message = message.replace(url, redact_url(url))
        return NotificationDeliveryStatus.FAILED, message[:2000]


def redact_url(url: str) -> str:
    """`https://host[:port]/…` — a webhook/ntfy/Discord URL's path (and
    query) *is* its secret (Discord's `/api/webhooks/<id>/<token>`, Slack's
    `/services/...`, an ntfy topic), so the delivery history, error text and
    a view-only account keep only where it goes, never how to post there.
    A URL too malformed to split (a broken `[v6]` host, a port out of
    range) redacts to nothing at all."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return "…"
    if not parts.scheme or not parts.hostname:
        return "…"
    host = parts.hostname + (f":{port}" if port else "")
    rest = "/…" if parts.path.strip("/") or parts.query else ""
    return f"{parts.scheme}://{host}{rest}"


def delivery_target(channel: str, url: str | None, recipient: str | None) -> str:
    """What the delivery history shows as a push's target — never a token
    or a secret URL path."""
    if channel == C.TELEGRAM.value:
        return f"Telegram chat {recipient}"
    if channel == C.PUSHOVER.value:
        return f"Pushover {recipient}"
    return redact_url(url) if url else CHANNEL_NAMES.get(channel, channel)
