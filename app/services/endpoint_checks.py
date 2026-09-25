"""TLS certificate and HTTP endpoint checks, run from the debcontrol
server (Celery worker), plus the pure state machine that turns each result
into notification events.

Probes:
- `probe_http` — GET with redirects followed; up when the status matches
  `expected_status` (or is < 400 when none is set) and, if `expected_body`
  is set, that text appears in the first `MAX_BODY_BYTES` of the response
  body (read streamed, so a huge response is never loaded whole). An https URL also gets
  a `probe_tls` of its host so the certificate expiry is known.
- `probe_tls` — a TLS handshake; the certificate's `notAfter` is read even
  when verification fails (expired/self-signed), via a second, unverified
  handshake, so an expired certificate still reports *when* it expired.

Targets are admin-configured (`machine.manage`) and requested from the
debcontrol host, the same trust level as a notification webhook URL.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx
from cryptography import x509

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.notification_rule import NotificationEventType

# A single failed probe is often a blip; announce an outage after this many
# consecutive failures.
FAILURES_BEFORE_DOWN = 2

# How much of a response body `expected_body` is searched in.
MAX_BODY_BYTES = 1024 * 1024


@dataclass
class ProbeResult:
    ok: bool
    error: str | None = None
    status_code: int | None = None
    latency_ms: float | None = None
    cert_expires_at: datetime | None = None


def parse_tls_target(target: str) -> tuple[str, int]:
    """`host:port` (or bare `host`, port 443; `[v6]:port` for IPv6)."""
    value = target.strip()
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port else 443
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit() and host:
        return host, int(port)
    return value, 443


def validate_target(kind: str, target: str) -> str | None:
    """An error message, or None if `target` fits `kind`."""
    value = target.strip()
    if not value:
        return "Target is required."
    if kind == "http":
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return "An HTTP check needs a full http:// or https:// URL."
        return None
    if kind == "tls":
        if "://" in value or "/" in value:
            return "A TLS check needs host or host:port, not a URL."
        try:
            host, port = parse_tls_target(value)
        except ValueError:
            return "Invalid port."
        if not host or not 0 < port < 65536:
            return "Invalid host or port."
        return None
    return "Unknown check type."


def _not_after(der: bytes | None) -> datetime | None:
    if not der:
        return None
    return x509.load_der_x509_certificate(der).not_valid_after_utc


async def _handshake(host: str, port: int, timeout_seconds: float, verify: bool) -> bytes | None:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=context, server_hostname=host), timeout_seconds
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        return ssl_object.getpeercert(binary_form=True) if ssl_object else None
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def probe_tls(target: str, timeout_seconds: float, verify: bool = True) -> ProbeResult:
    host, port = parse_tls_target(target)
    started = time.perf_counter()
    try:
        der = await _handshake(host, port, timeout_seconds, verify)
        latency = (time.perf_counter() - started) * 1000
        return ProbeResult(ok=True, latency_ms=round(latency, 1), cert_expires_at=_not_after(der))
    except ssl.SSLCertVerificationError as exc:
        expires: datetime | None = None
        with contextlib.suppress(Exception):
            expires = _not_after(await _handshake(host, port, timeout_seconds, verify=False))
        return ProbeResult(
            ok=False, error=f"Certificate: {exc.verify_message}", cert_expires_at=expires
        )
    except TimeoutError:
        return ProbeResult(ok=False, error="Timed out.")
    except (OSError, ssl.SSLError, ValueError) as exc:
        return ProbeResult(ok=False, error=str(exc) or exc.__class__.__name__)


async def _read_body_prefix(response: httpx.Response) -> str:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= MAX_BODY_BYTES:
            break
    return b"".join(chunks)[:MAX_BODY_BYTES].decode(response.encoding or "utf-8", "replace")


async def probe_http(
    url: str,
    timeout_seconds: float,
    expected_status: int | None,
    verify: bool = True,
    expected_body: str | None = None,
) -> ProbeResult:
    started = time.perf_counter()
    try:
        async with (
            httpx.AsyncClient(
                timeout=timeout_seconds, verify=verify, follow_redirects=True
            ) as client,
            client.stream("GET", url, headers={"User-Agent": "debcontrol-check"}) as response,
        ):
            code = response.status_code
            body = await _read_body_prefix(response) if expected_body else ""
    except httpx.TimeoutException:
        result = ProbeResult(ok=False, error="Timed out.")
    except httpx.HTTPError as exc:
        result = ProbeResult(ok=False, error=str(exc) or exc.__class__.__name__)
    else:
        latency = round((time.perf_counter() - started) * 1000, 1)
        status_ok = code == expected_status if expected_status is not None else code < 400
        body_ok = not expected_body or expected_body in body
        error = None
        if not status_ok:
            error = f"HTTP {code}"
        elif not body_ok:
            error = f'HTTP {code}, but the response doesn\'t contain "{expected_body}"'
        result = ProbeResult(
            ok=status_ok and body_ok,
            status_code=code,
            latency_ms=latency,
            error=error,
        )
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        tls_target = f"{parts.hostname}:{parts.port or 443}"
        tls = await probe_tls(tls_target, timeout_seconds, verify=verify)
        result.cert_expires_at = tls.cert_expires_at
    return result


async def run_probe(check: EndpointCheck) -> ProbeResult:
    if check.kind == "http":
        return await probe_http(
            check.target,
            check.timeout_seconds,
            check.expected_status,
            check.verify_tls,
            expected_body=check.expected_body,
        )
    return await probe_tls(check.target, check.timeout_seconds, check.verify_tls)


def apply_result(
    check: EndpointCheck, result: ProbeResult, now: datetime
) -> list[tuple[NotificationEventType, dict[str, str]]]:
    """Store `result` on `check` and return the notification events it
    triggers: ENDPOINT_DOWN on reaching `FAILURES_BEFORE_DOWN` consecutive
    failures, ENDPOINT_RECOVERED on the first success after an announced
    outage, CERT_EXPIRING once per certificate when it's within
    `cert_warn_days` of expiry (or already expired)."""
    check.last_checked_at = now
    check.last_ok = result.ok
    check.last_error = (result.error or None) and result.error[:500]
    check.last_status_code = result.status_code
    check.last_latency_ms = result.latency_ms
    if result.cert_expires_at is not None:
        check.cert_expires_at = result.cert_expires_at.replace(tzinfo=None)

    context = {
        "endpoint_name": check.name,
        "endpoint_target": check.target,
        "details": result.error or "",
    }
    events: list[tuple[NotificationEventType, dict[str, str]]] = []
    if result.ok:
        if check.down_notified:
            events.append((NotificationEventType.ENDPOINT_RECOVERED, context))
        check.consecutive_failures = 0
        check.down_notified = False
    else:
        check.consecutive_failures += 1
        if check.consecutive_failures >= FAILURES_BEFORE_DOWN and not check.down_notified:
            check.down_notified = True
            events.append((NotificationEventType.ENDPOINT_DOWN, context))

    expires = check.cert_expires_at
    if expires is not None:
        expires_utc = expires.replace(tzinfo=UTC)
        days_left = (expires_utc - now).total_seconds() / 86400
        if days_left <= check.cert_warn_days and check.cert_warned_for != expires:
            check.cert_warned_for = expires
            events.append(
                (
                    NotificationEventType.CERT_EXPIRING,
                    {
                        **context,
                        "days": str(max(0, int(days_left))),
                        "expires_at": expires_utc.strftime("%Y-%m-%d %H:%M UTC"),
                    },
                )
            )
    return events


def is_due(check: EndpointCheck, now: datetime) -> bool:
    if not check.enabled:
        return False
    if check.last_checked_at is None:
        return True
    last = check.last_checked_at.replace(tzinfo=UTC)
    return now - last >= timedelta(seconds=max(check.interval_seconds, 30))
