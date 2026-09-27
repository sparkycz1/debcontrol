"""ICMP ping, TCP port and DNS probes for endpoint checks — run from the
debcontrol server (Celery worker), like the HTTP/TLS ones in
`app.services.endpoint_checks`.

- **ping** sends one ICMP echo request through an *unprivileged* ICMP
  socket (`SOCK_DGRAM`, `IPPROTO_ICMP`) — no raw socket, no extra
  capability. Linux allows it for groups within `net.ipv4.ping_group_range`,
  which Docker sets to every group inside containers by default; where it
  isn't allowed the check fails with a message saying so.
- **tcp** opens a TCP connection to `host:port` and closes it again.
- **dns** resolves a name — through the system resolver, or through one
  specific server with `name@server` (`nas.lan@192.168.1.53`) to check
  that exact resolver (a Pi-hole, AdGuard Home, a router). The expected
  text, when set, must be one of the addresses returned.

Every probe returns an `endpoint_checks.ProbeResult`-shaped tuple through
`run(...)` and never raises.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import secrets
import socket
import struct
import time

# --- targets ---------------------------------------------------------------


def split_host_port(target: str) -> tuple[str, int | None]:
    """`host:port`, `[v6]:port` or a bare host (port None)."""
    value = target.strip()
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        port = rest.lstrip(":")
        return host, int(port) if port.isdigit() else None
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        return host, int(port) if port.isdigit() else None
    return value, None


def split_dns_target(target: str) -> tuple[str, str | None]:
    """`name` or `name@server` -> (name, server or None)."""
    name, sep, server = target.strip().partition("@")
    return name.strip().rstrip("."), (server.strip() or None) if sep else None


def _valid_hostname(value: str) -> bool:
    if not value or len(value) > 253 or "/" in value or " " in value:
        return False
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(value)
        return True
    return all(label and len(label) <= 63 for label in value.rstrip(".").split("."))


def validate_target(kind: str, target: str) -> str | None:
    """An error message, or None when `target` fits `kind`."""
    value = target.strip()
    if kind == "ping":
        return None if _valid_hostname(value) else "A ping check needs a host name or IP address."
    if kind == "tcp":
        host, port = split_host_port(value)
        if not _valid_hostname(host) or port is None or not 0 < port < 65536:
            return "A TCP check needs host:port."
        return None
    if kind == "dns":
        name, server = split_dns_target(value)
        if not _valid_hostname(name):
            return "A DNS check needs a name to resolve (optionally name@server)."
        if server is not None:
            try:
                ipaddress.ip_address(server)
            except ValueError:
                return "The DNS server after @ must be an IP address."
        return None
    return "Unknown check type."


# --- ping --------------------------------------------------------------------


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo_request(ident: int, sequence: int, payload: bytes, *, v6: bool = False) -> bytes:
    """One ICMP (type 8) / ICMPv6 (type 128) echo request."""
    icmp_type = 128 if v6 else 8
    header = struct.pack("!BBHHH", icmp_type, 0, 0, ident, sequence)
    checksum = 0 if v6 else _checksum(header + payload)  # the kernel fills ICMPv6's
    return struct.pack("!BBHHH", icmp_type, 0, checksum, ident, sequence) + payload


def is_echo_reply(packet: bytes, payload: bytes, *, v6: bool = False) -> bool:
    """An echo reply carrying our payload. Unprivileged ICMP sockets hand
    back the ICMP message itself (no IP header) and rewrite the identifier,
    so the payload is what identifies our reply."""
    if len(packet) < 8:
        return False
    return packet[0] == (129 if v6 else 0) and packet[8:] == payload


async def _resolve(host: str, timeout_seconds: float) -> tuple[int, str]:
    loop = asyncio.get_running_loop()
    async with asyncio.timeout(timeout_seconds):
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    if not infos:
        raise OSError(f"{host} doesn't resolve")
    family, _type, _proto, _canon, sockaddr = infos[0]
    return family, str(sockaddr[0])


async def probe_ping(target: str, timeout_seconds: float) -> tuple[bool, str | None, float | None]:
    try:
        family, address = await _resolve(target.strip(), timeout_seconds)
    except (OSError, TimeoutError) as exc:
        return False, f"Can't resolve {target}: {exc}", None
    v6 = family == socket.AF_INET6
    proto = socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM, proto)
    except PermissionError:
        return (
            False,
            "ICMP isn't permitted for this process (net.ipv4.ping_group_range) — "
            "use a TCP check instead.",
            None,
        )
    except OSError as exc:
        return False, f"Can't open an ICMP socket: {exc}", None
    payload = os.urandom(16)
    packet = build_echo_request(secrets.randbelow(0xFFFE) + 1, 1, payload, v6=v6)
    loop = asyncio.get_running_loop()
    sock.setblocking(False)
    started = time.monotonic()
    try:
        await loop.sock_sendto(sock, packet, (address, 0))
        async with asyncio.timeout(timeout_seconds):
            while True:
                data = await loop.sock_recv(sock, 2048)
                if is_echo_reply(data, payload, v6=v6):
                    break
    except TimeoutError:
        return False, f"No reply from {address} within {timeout_seconds:g} s", None
    except OSError as exc:
        return False, f"Ping to {address} failed: {exc}", None
    finally:
        sock.close()
    return True, None, (time.monotonic() - started) * 1000


# --- tcp -----------------------------------------------------------------------


async def probe_tcp(target: str, timeout_seconds: float) -> tuple[bool, str | None, float | None]:
    host, port = split_host_port(target)
    started = time.monotonic()
    try:
        async with asyncio.timeout(timeout_seconds):
            _reader, writer = await asyncio.open_connection(host, port)
    except TimeoutError:
        return False, f"No connection to {target} within {timeout_seconds:g} s", None
    except OSError as exc:
        return False, f"Connection to {target} failed: {exc}", None
    latency = (time.monotonic() - started) * 1000
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()
    return True, None, latency


# --- dns -----------------------------------------------------------------------

_TYPE_A = 1
_TYPE_AAAA = 28


def build_dns_query(name: str, qtype: int, query_id: int) -> bytes:
    """A standard recursive query for one name."""
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(part)]) + part.encode("idna") for part in name.rstrip(".").split(".") if part
    )
    return header + labels + b"\0" + struct.pack("!HH", qtype, 1)


def _skip_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += length + 1


def parse_dns_answers(data: bytes, query_id: int) -> tuple[int, list[str]]:
    """(rcode, A/AAAA addresses) from a response to `query_id`. Raises
    ValueError for a malformed or foreign packet."""
    if len(data) < 12:
        raise ValueError("short DNS response")
    rid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != query_id:
        raise ValueError("DNS response id mismatch")
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset) + 4
    addresses: list[str] = []
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        rtype, _rclass, _ttl, length = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + length]
        offset += length
        if rtype == _TYPE_A and length == 4:
            addresses.append(str(ipaddress.IPv4Address(rdata)))
        elif rtype == _TYPE_AAAA and length == 16:
            addresses.append(str(ipaddress.IPv6Address(rdata)))
    return flags & 0x000F, addresses


class _DnsProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.response: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr: object) -> None:
        if not self.response.done():
            self.response.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.response.done():
            self.response.set_exception(exc)


async def _query_server(
    name: str, server: str, qtype: int, timeout_seconds: float
) -> tuple[int, list[str]]:
    loop = asyncio.get_running_loop()
    query_id = secrets.randbelow(0xFFFF)
    transport, protocol = await loop.create_datagram_endpoint(
        _DnsProtocol, remote_addr=(server, 53)
    )
    try:
        transport.sendto(build_dns_query(name, qtype, query_id))
        async with asyncio.timeout(timeout_seconds):
            data = await protocol.response
    finally:
        transport.close()
    return parse_dns_answers(data, query_id)


_RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


async def probe_dns(
    target: str, timeout_seconds: float, expected: str | None
) -> tuple[bool, str | None, float | None]:
    name, server = split_dns_target(target)
    started = time.monotonic()
    addresses: list[str] = []
    try:
        if server is None:
            loop = asyncio.get_running_loop()
            async with asyncio.timeout(timeout_seconds):
                infos = await loop.getaddrinfo(name, None, type=socket.SOCK_STREAM)
            addresses = sorted({str(info[4][0]) for info in infos})
        else:
            for qtype in (_TYPE_A, _TYPE_AAAA):
                rcode, found = await _query_server(name, server, qtype, timeout_seconds)
                if rcode and qtype == _TYPE_A:
                    return False, f"{server} answered {_RCODES.get(rcode, rcode)} for {name}", None
                addresses += found
    except TimeoutError:
        return False, f"No DNS answer for {name} within {timeout_seconds:g} s", None
    except (OSError, ValueError) as exc:
        return False, f"Resolving {name} failed: {exc}", None
    latency = (time.monotonic() - started) * 1000
    if not addresses:
        return False, f"{name} has no A/AAAA record", latency
    if expected and expected.strip() not in addresses:
        return False, f"{name} resolved to {', '.join(addresses)}, not {expected.strip()}", latency
    return True, None, latency
