"""Connectivity seen from the managed machine itself: ping to its default
gateway and to an internet address, how long a DNS lookup takes, and
whether the clock is synchronised (and how far off it is).

It answers a question the checks run *from debcontrol* can't: when a
machine misbehaves, is it the machine, its local network, or the line out
of the site? A gateway that answers while the internet target doesn't is
an outage upstream, not on the host.

Run with every monitoring sample (`app.ssh.monitoring`), in the
background while the CPU probe sleeps, and on demand from the Overview's
"Test connectivity" (`app.tasks.jobs._test_machine_connectivity`, with
more pings). Everything is read-only and needs no root: `ping` works for
an ordinary account on current Debian/Ubuntu (file capability or
`net.ipv4.ping_group_range`); where it doesn't, or a tool is missing,
that reading is simply absent (None), never an error.

The two configurable values (Settings → Checks & retention → Connectivity)
reach the shell only through `shlex.quote`, and are validated when saved
(`valid_target`).
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import TypedDict

from app.db.models.machine import Machine
from app.ssh.pool import machine_connection
from app.ssh.shell import output_text

DEFAULT_INTERNET_TARGET = "1.1.1.1"
DEFAULT_DNS_NAME = "debian.org"

# Pings per target: a few for a sample, more for the manual test.
SAMPLE_PINGS = 3
TEST_PINGS = 5

_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")


def valid_target(value: str) -> bool:
    """An IP address or a plain host name — nothing a shell could read as
    an option or a second word."""
    value = value.strip()
    if not value or len(value) > 253 or value.startswith("-"):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return all(_LABEL_RE.match(label) for label in value.removesuffix(".").split("."))


def _ping(tag: str, target: str, count: int) -> str:
    # -n: no reverse lookups; -q: just the summary; -i 0.2 is the shortest
    # interval an ordinary account may use; -w caps the whole run.
    deadline = count + 1
    return (
        f"echo @@{tag}; "
        f"ping -n -q -c {count} -i 0.2 -W 1 -w {deadline} {target} 2>/dev/null | tail -n 3"
    )


def command(internet_target: str, dns_name: str, *, pings: int = SAMPLE_PINGS) -> str:
    """The probe as one shell snippet; its output is read by `parse`."""
    target = shlex.quote(internet_target)
    name = shlex.quote(dns_name)
    return (
        "GW=\"$(ip -4 route show default 2>/dev/null "
        "| awk '$1 == \"default\" {print $3; exit}')\"; "
        'echo "@@GATEWAY $GW"; '
        "if command -v ping >/dev/null 2>&1; then "
        f'if [ -n "$GW" ]; then {_ping("GWPING", chr(34) + "$GW" + chr(34), pings)}; fi; '
        f"{_ping('NETPING', target, pings)}; "
        "fi; "
        # DNS: how long one lookup through the machine's own resolver takes.
        # `date +%s%N` is in milliseconds only where %N is supported; the
        # parser drops a value that isn't a plain number.
        "T=; command -v timeout >/dev/null 2>&1 && T='timeout 4'; "
        "if command -v getent >/dev/null 2>&1; then "
        f"S=\"$(date +%s%N)\"; $T getent ahosts {name} >/dev/null 2>&1; R=$?; E=\"$(date +%s%N)\"; "
        'echo "@@DNS $R $S $E"; '
        "elif command -v nslookup >/dev/null 2>&1; then "
        f"S=\"$(date +%s%N)\"; $T nslookup {name} >/dev/null 2>&1; R=$?; E=\"$(date +%s%N)\"; "
        'echo "@@DNS $R $S $E"; '
        "fi; "
        # NTP: synchronised at all (systemd), and the current offset from
        # chrony or systemd-timesyncd, whichever runs.
        "if command -v timedatectl >/dev/null 2>&1; then "
        'echo "@@NTPSYNC $(timedatectl show -p NTPSynchronized --value 2>/dev/null)"; '
        "timedatectl timesync-status 2>/dev/null "
        "| awk '$1 == \"Offset:\" {print \"@@TIMESYNC\", $2; exit}'; "
        "fi; "
        "if command -v chronyc >/dev/null 2>&1; then "
        "chronyc -n tracking 2>/dev/null "
        "| awk -F': ' '/^System time/ {print \"@@CHRONY\", $2; exit}'; "
        "fi"
    )


class Connectivity(TypedDict):
    gateway: str | None
    gateway_latency_ms: float | None
    gateway_loss_percent: float | None
    internet_latency_ms: float | None
    internet_loss_percent: float | None
    # True = resolved, False = the lookup failed, None = not measured.
    dns_ok: bool | None
    dns_ms: float | None
    ntp_synced: bool | None
    # Positive = the machine's clock is ahead.
    ntp_offset_ms: float | None


_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)% packet loss")
# iputils: "rtt min/avg/max/mdev = 0.3/0.4/0.5/0.1 ms"; BusyBox:
# "round-trip min/avg/max = 0.3/0.4/0.5 ms".
_RTT_RE = re.compile(r"=\s*[\d.]+/([\d.]+)/")
_TIMESYNC_RE = re.compile(r"^([+-]?\d+(?:\.\d+)?)(ns|us|µs|ms|s|min)$")
_TIMESYNC_SCALE = {"ns": 1e-6, "us": 1e-3, "µs": 1e-3, "ms": 1.0, "s": 1000.0, "min": 60000.0}
_CHRONY_RE = re.compile(r"^([\d.]+) seconds (fast|slow)")


def _ping_stats(lines: list[str]) -> tuple[float | None, float | None]:
    """(average round trip in ms, loss in percent) from a ping summary."""
    text = "\n".join(lines)
    loss_match = _LOSS_RE.search(text)
    if loss_match is None:
        return None, None
    loss = float(loss_match.group(1))
    rtt_match = _RTT_RE.search(text)
    latency = round(float(rtt_match.group(1)), 2) if rtt_match and loss < 100 else None
    return latency, loss


def _dns(fields: list[str]) -> tuple[bool | None, float | None]:
    if not fields or not fields[0].isdecimal():
        return None, None
    ok = fields[0] == "0"
    if len(fields) == 3 and fields[1].isdecimal() and fields[2].isdecimal():
        elapsed = (int(fields[2]) - int(fields[1])) / 1_000_000
        if 0 <= elapsed < 60_000:
            return ok, round(elapsed, 1) if ok else None
    return ok, None


def parse(raw: str) -> Connectivity:
    """Read `command`'s output. Pure function, no I/O."""
    result = Connectivity(
        gateway=None,
        gateway_latency_ms=None,
        gateway_loss_percent=None,
        internet_latency_ms=None,
        internet_loss_percent=None,
        dns_ok=None,
        dns_ms=None,
        ntp_synced=None,
        ntp_offset_ms=None,
    )
    blocks: dict[str, list[str]] = {}
    current: list[str] | None = None
    timesync_offset: float | None = None
    chrony_offset: float | None = None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("@@"):
            tag, _, rest = line[2:].partition(" ")
            rest = rest.strip()
            current = None
            if tag in ("GWPING", "NETPING"):
                current = blocks.setdefault(tag, [])
            elif tag == "GATEWAY":
                try:
                    result["gateway"] = str(ipaddress.ip_address(rest)) if rest else None
                except ValueError:
                    result["gateway"] = None
            elif tag == "DNS":
                result["dns_ok"], result["dns_ms"] = _dns(rest.split())
            elif tag == "NTPSYNC":
                result["ntp_synced"] = {"yes": True, "no": False}.get(rest)
            elif tag == "TIMESYNC":
                match = _TIMESYNC_RE.match(rest)
                if match:
                    timesync_offset = float(match.group(1)) * _TIMESYNC_SCALE[match.group(2)]
            elif tag == "CHRONY":
                match = _CHRONY_RE.match(rest)
                if match:
                    seconds = float(match.group(1))
                    chrony_offset = seconds * 1000 * (1 if match.group(2) == "fast" else -1)
            continue
        if current is not None:
            current.append(line)
    if "GWPING" in blocks:
        result["gateway_latency_ms"], result["gateway_loss_percent"] = _ping_stats(
            blocks["GWPING"]
        )
    if "NETPING" in blocks:
        result["internet_latency_ms"], result["internet_loss_percent"] = _ping_stats(
            blocks["NETPING"]
        )
    offset = chrony_offset if chrony_offset is not None else timesync_offset
    if offset is not None:
        result["ntp_offset_ms"] = round(offset, 3)
    return result


async def run_test(
    machine: Machine, secret: str | None, timeout_seconds: int, internet_target: str, dns_name: str
) -> Connectivity:
    """The Overview's "Test connectivity": the same probe, more pings."""
    probe = command(internet_target, dns_name, pings=TEST_PINGS)
    async with machine_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(probe, check=False, timeout=timeout_seconds + 20)
    return parse(output_text(result))
