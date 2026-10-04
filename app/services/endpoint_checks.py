"""TLS certificate and HTTP endpoint checks, run from the debcontrol
server (Celery worker), plus the pure state machine that turns each result
into notification events.

Probes:
- `probe_http` — GET with redirects followed; up when the status matches
  `expected_status` (or is < 400 when none is set) and the body assertions
  hold, all checked against the first `MAX_BODY_BYTES` of the response
  (read streamed, so a huge response is never loaded whole): the
  `expected_body` text appears, the `unexpected_body` text doesn't, and the
  `json_path` assertion (`evaluate_json_path`) passes. An https URL also
  gets a `probe_tls` of its host so the certificate expiry is known.
- `probe_tls` — a TLS handshake; the certificate's `notAfter` is read even
  when verification fails (expired/self-signed), via a second, unverified
  handshake, so an expired certificate still reports *when* it expired.

Plus ICMP ping, TCP port and DNS checks (`app.services.network_probes`).
Every kind also fails when it answered slower than `max_latency_ms`.

Targets are admin-configured (`machine.manage`) and requested from the
debcontrol host, the same trust level as a notification webhook URL.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx2
from cryptography import x509

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.notification_rule import NotificationEventType
from app.services import acknowledgements, network_probes

# A single failed probe is often a blip; announce an outage after this many
# consecutive failures.
FAILURES_BEFORE_DOWN = 2

# How much of a response body `expected_body` is searched in.
MAX_BODY_BYTES = 1024 * 1024


@dataclass
class BodyAssertions:
    """What an HTTP check's response body has to satisfy — all optional."""

    expected: str | None = None
    unexpected: str | None = None
    json_path: str | None = None
    json_expected: str | None = None

    @property
    def needs_body(self) -> bool:
        return bool(self.expected or self.unexpected or self.json_path)


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
    if kind in ("ping", "tcp", "dns"):
        return network_probes.validate_target(kind, value)
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


async def _read_body_prefix(response: httpx2.Response) -> str:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= MAX_BODY_BYTES:
            break
    return b"".join(chunks)[:MAX_BODY_BYTES].decode(response.encoding or "utf-8", "replace")


def _json_text(value: object) -> str:
    """A JSON value as the text `json_expected` is compared with: strings
    bare (`ok`, not `"ok"`), everything else as JSON (`true`, `42`, `null`)."""
    return value if isinstance(value, str) else json.dumps(value)


def evaluate_json_path(body: str, path: str, expected: str | None) -> str | None:
    """An error message, or None when the assertion holds. `path` is a
    dotted path (`status`, `checks.db.ok`, `items.0.state`; a leading `$.`
    is accepted), a number indexing into a list. With `expected` the value
    must equal it as JSON text (see `_json_text`); without, it must exist
    and not be null or false."""
    try:
        value: object = json.loads(body)
    except ValueError:
        return "The response isn't valid JSON."
    clean = path.strip().removeprefix("$").lstrip(".")
    for part in [p for p in clean.split(".") if p] if clean else []:
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.lstrip("-").isdigit() and (
            -len(value) <= int(part) < len(value)
        ):
            value = value[int(part)]
        else:
            return f'JSON path "{path}" not found in the response'
    if expected is None:
        if value is None or value is False:
            return f'JSON path "{path}" is {_json_text(value)}'
        return None
    actual = _json_text(value)
    if actual != expected.strip():
        return f'JSON path "{path}" is {actual[:100]}, expected {expected.strip()}'
    return None


def _check_body(body: str, assertions: BodyAssertions) -> str | None:
    if assertions.expected and assertions.expected not in body:
        return f'the response doesn\'t contain "{assertions.expected}"'
    if assertions.unexpected and assertions.unexpected in body:
        return f'the response contains "{assertions.unexpected}"'
    if assertions.json_path:
        return evaluate_json_path(body, assertions.json_path, assertions.json_expected)
    return None


async def probe_http(
    url: str,
    timeout_seconds: float,
    expected_status: int | None,
    verify: bool = True,
    expected_body: str | None = None,
    assertions: BodyAssertions | None = None,
) -> ProbeResult:
    """`expected_body` is shorthand for `assertions=BodyAssertions(expected=...)`
    (kept for existing callers)."""
    body_rules = assertions or BodyAssertions(expected=expected_body)
    started = time.perf_counter()
    try:
        async with (
            httpx2.AsyncClient(
                timeout=timeout_seconds, verify=verify, follow_redirects=True
            ) as client,
            client.stream("GET", url, headers={"User-Agent": "debcontrol-check"}) as response,
        ):
            code = response.status_code
            body = await _read_body_prefix(response) if body_rules.needs_body else ""
    except httpx2.TimeoutException:
        result = ProbeResult(ok=False, error="Timed out.")
    except httpx2.HTTPError as exc:
        result = ProbeResult(ok=False, error=str(exc) or exc.__class__.__name__)
    else:
        latency = round((time.perf_counter() - started) * 1000, 1)
        status_ok = code == expected_status if expected_status is not None else code < 400
        body_error = _check_body(body, body_rules) if status_ok else None
        error = None
        if not status_ok:
            error = f"HTTP {code}"
        elif body_error:
            error = f"HTTP {code}, but {body_error}"
        result = ProbeResult(
            ok=status_ok and body_error is None,
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


def apply_latency_limit(result: ProbeResult, max_latency_ms: int | None) -> ProbeResult:
    """Turn an otherwise-successful but too-slow probe into a failure."""
    if (
        result.ok
        and max_latency_ms
        and result.latency_ms is not None
        and result.latency_ms > max_latency_ms
    ):
        result.ok = False
        result.error = f"Too slow: {result.latency_ms:.0f} ms (limit {max_latency_ms} ms)"
    return result


async def run_probe(check: EndpointCheck) -> ProbeResult:
    if check.kind == "http":
        result = await probe_http(
            check.target,
            check.timeout_seconds,
            check.expected_status,
            check.verify_tls,
            assertions=BodyAssertions(
                expected=check.expected_body,
                unexpected=check.unexpected_body,
                json_path=check.json_path,
                json_expected=check.json_expected,
            ),
        )
    elif check.kind == "tls":
        result = await probe_tls(check.target, check.timeout_seconds, check.verify_tls)
    else:
        if check.kind == "ping":
            ok, error, latency = await network_probes.probe_ping(
                check.target, check.timeout_seconds
            )
        elif check.kind == "tcp":
            ok, error, latency = await network_probes.probe_tcp(check.target, check.timeout_seconds)
        else:
            ok, error, latency = await network_probes.probe_dns(
                check.target, check.timeout_seconds, check.expected_body
            )
        result = ProbeResult(ok=ok, error=error, latency_ms=latency)
    return apply_latency_limit(result, check.max_latency_ms)


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
        # Up again: whatever was acknowledged is over.
        acknowledgements.clear(check)
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
