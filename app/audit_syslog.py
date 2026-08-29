"""Forward audit log entries to an external syslog server (e.g. a SIEM),
configured on the Settings page (`AppSettings.syslog_*`).

Best-effort, fire-and-forget: the `AuditLogEntry` row already written by
`app.audit.log_event` is always the source of truth (hash-chained,
queryable, exportable) — this is only ever a live mirror of it, and a
delivery failure here must never affect the action being audited or raise
back into the caller. See `log_event`'s call into `forward_to_syslog`.

Supports plain UDP, plain TCP, and TCP-over-TLS ("encrypted syslog", for
sending to a SIEM over a network you don't fully trust). Messages are
RFC 5424 formatted; the two TCP modes use RFC 6587 octet-counting framing
(`"<length> <message>"`) so the receiver can split a stream into messages —
UDP needs no framing, since one datagram is already one message.

All socket I/O is blocking (`socket`/`ssl` are simplest for one-shot sends
like this — no long-lived connection to manage) so it always runs off the
event loop via `asyncio.to_thread`, same pattern as `app.auth.ldap`'s
synchronous `ldap3` calls.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.db.models.app_settings import AppSettings
    from app.db.models.audit_log import AuditLogEntry

logger = logging.getLogger("debcontrol.audit_syslog")

_SOCKET_TIMEOUT_SECONDS = 3
_FACILITY_USER = 1  # RFC 5424 facility 1, "user-level messages".


def _severity_for_outcome(outcome_value: str) -> int:
    # RFC 5424 severities: lower number = more severe.
    if outcome_value == "success":
        return 5  # notice
    if outcome_value == "denied":
        return 4  # warning
    return 3  # error ("failure")


def _rfc5424_message(entry: AuditLogEntry) -> str:
    pri = _FACILITY_USER * 8 + _severity_for_outcome(entry.outcome.value)
    timestamp = entry.created_at.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    hostname = socket.gethostname() or "-"
    msg_id = (entry.action or "-").replace(" ", "_")[:32]
    detail = (
        f'actor="{entry.actor or "-"}" ip="{entry.ip_address or "-"}" '
        f'outcome="{entry.outcome.value}" '
        f'target="{entry.target_type or "-"}:{entry.target_id or "-"}" '
        f'summary="{entry.summary}"'
    )
    # "debcontrol" is the APP-NAME field; "-" (no PROCID), then MSGID, then
    # "-" for STRUCTURED-DATA (none), then the message itself.
    return f"<{pri}>1 {timestamp} {hostname} debcontrol - {msg_id} - {detail}"


def _send_sync(app_settings: AppSettings, message: str) -> None:
    from app.db.models.app_settings import SyslogProtocol  # local import: avoid a module cycle

    host = app_settings.syslog_host
    port = app_settings.syslog_port
    if not host:
        return

    if app_settings.syslog_protocol == SyslogProtocol.UDP:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_SOCKET_TIMEOUT_SECONDS)
            sock.sendto(message.encode("utf-8"), (host, port))
        return

    body = message.encode("utf-8")
    framed = str(len(body)).encode("ascii") + b" " + body
    with socket.create_connection((host, port), timeout=_SOCKET_TIMEOUT_SECONDS) as sock:
        if app_settings.syslog_protocol == SyslogProtocol.TLS:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.sendall(framed)
        else:
            sock.sendall(framed)


async def forward_to_syslog(app_settings: AppSettings, entry: AuditLogEntry) -> None:
    """No-op unless `syslog_enabled` and a host is configured. Never raises
    — logs a warning and swallows any failure, since a SIEM being
    unreachable must never be allowed to affect the action being audited."""
    if not app_settings.syslog_enabled or not app_settings.syslog_host:
        return
    message = _rfc5424_message(entry)
    try:
        await asyncio.to_thread(_send_sync, app_settings, message)
    except OSError:
        logger.warning(
            "Failed to forward audit entry to syslog %s:%s",
            app_settings.syslog_host,
            app_settings.syslog_port,
            exc_info=True,
        )
