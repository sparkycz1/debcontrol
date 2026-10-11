"""Endpoint checks run *from a managed machine* instead of from the
debcontrol server (`EndpointCheck.source_machine_id`) — the way to check
something only that machine can reach: a service on an internal network,
a database port behind a firewall, the name an internal resolver gives.

Each probe is one shell command over the machine's ordinary SSH
connection, using what a Debian/Ubuntu machine has anyway (`curl`,
`openssl`, `ping`, `bash`'s `/dev/tcp`, `getent`, `dig` for a named
resolver). Nothing is installed and no root is needed. The command prints
its own result line; `parse_output` turns that back into the same
`ProbeResult` the server-side probes produce, so everything after the
probe (latency limit, notifications, history, SLA) is shared.

The target is validated (`endpoint_checks.validate_target`) when the check
is saved and quoted here on top of that.
"""

from __future__ import annotations

import shlex
from datetime import UTC, datetime
from urllib.parse import urlsplit

import asyncssh

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine import Machine
from app.services import network_probes
from app.services.endpoint_checks import (
    MAX_BODY_BYTES,
    BodyAssertions,
    ProbeResult,
    _check_body,
    parse_tls_target,
)
from app.ssh.client import open_connection
from app.ssh.exceptions import SSHConnectionError

# The line every probe command ends with: exit status and elapsed
# milliseconds, measured on the machine itself (so the SSH round trip is
# not counted as the service's latency).
_MARKER = "__DEBCONTROL_PROBE__"
# curl's own trailer, on its own line after the body.
_HTTP_MARKER = "__DEBCONTROL_HTTP__"

# Exit status of the shell when the tool a probe needs is not installed.
_MISSING_TOOL = 127


def _timed(command: str) -> str:
    """`command`, followed by the marker line with its exit status and how
    long it took."""
    return (
        "s=$(date +%s%N); "
        f"{command}; rc=$?; "
        "e=$(date +%s%N); "
        f'echo; echo "{_MARKER} $rc $(( (e - s) / 1000000 ))"'
    )


def _http_command(check: EndpointCheck) -> str:
    assertions = _assertions(check)
    options = ["-sS", "-m", str(int(check.timeout_seconds))]
    if not check.verify_tls:
        options.append("-k")
    if assertions.needs_body:
        options += ["--max-filesize", str(MAX_BODY_BYTES)]
    else:
        options += ["-o", "/dev/null"]
    write_out = shlex.quote(f"\n{_HTTP_MARKER} %{{http_code}}\n")
    return _timed(
        f"curl {' '.join(options)} -w {write_out} -- {shlex.quote(check.target)} 2>&1"
    )


def _tls_command(check: EndpointCheck) -> str:
    host, port = parse_tls_target(check.target)
    verify = "-verify_return_error " if check.verify_tls else ""
    target = shlex.quote(f"{host}:{port}")
    return _timed(
        f"timeout {int(check.timeout_seconds)} openssl s_client -connect {target} "
        f"-servername {shlex.quote(host)} {verify}</dev/null 2>&1 "
        "| openssl x509 -noout -enddate 2>&1"
    )


def _ping_command(check: EndpointCheck) -> str:
    return _timed(
        f"ping -c 1 -W {int(check.timeout_seconds)} -- {shlex.quote(check.target.strip())} 2>&1"
    )


def _tcp_command(check: EndpointCheck) -> str:
    host, port = network_probes.split_host_port(check.target)
    inner = shlex.quote(f"exec 3<>/dev/tcp/{host}/{port}")
    return _timed(f"timeout {int(check.timeout_seconds)} bash -c {inner} 2>&1")


def _dns_command(check: EndpointCheck) -> str:
    name, server = network_probes.split_dns_target(check.target)
    if server:
        return _timed(
            f"dig +short +time={int(check.timeout_seconds)} +tries=1 "
            f"@{shlex.quote(server)} {shlex.quote(name)} A {shlex.quote(name)} AAAA 2>&1"
        )
    return _timed(f"getent ahosts {shlex.quote(name)} 2>&1 | awk '{{print $1}}' | sort -u")


_COMMANDS = {
    "http": _http_command,
    "tls": _tls_command,
    "ping": _ping_command,
    "tcp": _tcp_command,
    "dns": _dns_command,
}
_TOOLS = {"http": "curl", "tls": "openssl", "ping": "ping", "tcp": "bash", "dns": "getent/dig"}


def build_command(check: EndpointCheck) -> str:
    return _COMMANDS[check.kind](check)


def _assertions(check: EndpointCheck) -> BodyAssertions:
    return BodyAssertions(
        expected=check.expected_body,
        unexpected=check.unexpected_body,
        json_path=check.json_path,
        json_expected=check.json_expected,
    )


def _split(output: str) -> tuple[str, int | None, float | None]:
    """(what the command printed, its exit status, elapsed ms)."""
    body, marker, tail = output.rpartition(_MARKER)
    if not marker:
        return output, None, None
    fields = tail.split()
    try:
        return body.rstrip("\n"), int(fields[0]), float(fields[1])
    except (IndexError, ValueError):
        return body.rstrip("\n"), None, None


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1][:300] if lines else ""


def _parse_http(check: EndpointCheck, body: str) -> ProbeResult:
    content, marker, tail = body.rpartition(_HTTP_MARKER)
    code = tail.strip() if marker else ""
    status = int(code) if code.isdigit() else 0
    if status == 0:
        return ProbeResult(ok=False, error=_last_line(content or body) or "No response.")
    result = ProbeResult(ok=True, status_code=status)
    expected = check.expected_status
    if (expected is not None and status != expected) or (expected is None and status >= 400):
        result.ok = False
        result.error = f"HTTP {status}" + (f" (expected {expected})" if expected else "")
        return result
    assertions = _assertions(check)
    if assertions.needs_body:
        problem = _check_body(content, assertions)
        if problem:
            result.ok = False
            result.error = problem
    return result


def _parse_tls(body: str) -> ProbeResult:
    for line in body.splitlines():
        if line.startswith("notAfter="):
            text = line.removeprefix("notAfter=").strip()
            try:
                expires = datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            except ValueError:
                break
            if expires <= datetime.now(UTC):
                return ProbeResult(
                    ok=False, error="The certificate has expired.", cert_expires_at=expires
                )
            return ProbeResult(ok=True, cert_expires_at=expires)
    return ProbeResult(ok=False, error=_last_line(body) or "TLS handshake failed.")


def _parse_dns(check: EndpointCheck, body: str) -> ProbeResult:
    addresses = [line.strip() for line in body.splitlines() if line.strip()]
    addresses = [a for a in addresses if not a.startswith(";")]
    if not addresses:
        return ProbeResult(ok=False, error="The name did not resolve.")
    wanted = (check.expected_body or "").strip()
    if wanted and wanted not in addresses:
        return ProbeResult(
            ok=False, error=f"Resolved to {', '.join(addresses[:5])}, expected {wanted}."
        )
    return ProbeResult(ok=True)


def parse_output(check: EndpointCheck, output: str) -> ProbeResult:
    """The result of `build_command(check)`'s output. Pure function."""
    body, status, elapsed = _split(output)
    if status is None:
        return ProbeResult(ok=False, error="The probe did not finish on the machine.")
    if status == _MISSING_TOOL:
        return ProbeResult(
            ok=False, error=f"{_TOOLS[check.kind]} is not installed on the machine."
        )
    if check.kind == "http":
        result = _parse_http(check, body)
    elif check.kind == "tls":
        result = _parse_tls(body)
    elif check.kind == "dns":
        result = _parse_dns(check, body)
    elif status == 0:
        result = ProbeResult(ok=True)
    else:
        result = ProbeResult(
            ok=False,
            error=(
                "No reply."
                if check.kind == "ping"
                else (_last_line(body) or "Connection failed.")
            ),
        )
    result.latency_ms = elapsed
    return result


def source_host(check: EndpointCheck) -> str:
    """The host a check talks to — for messages."""
    if check.kind == "http":
        return urlsplit(check.target).hostname or check.target
    return check.target


async def probe_from_machine(
    check: EndpointCheck, machine: Machine, secret: str | None, connect_timeout_seconds: int
) -> ProbeResult:
    """Run `check` on `machine`. A machine that cannot be reached is a
    failed probe with a message saying so — the check could not be made."""
    if not machine.host_key_fingerprint:
        return ProbeResult(
            ok=False, error=f'"{machine.name}" has no confirmed SSH host key yet.'
        )
    try:
        async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
            completed = await conn.run(
                build_command(check),
                check=False,
                timeout=connect_timeout_seconds + check.timeout_seconds + 10,
            )
    except (SSHConnectionError, asyncssh.Error, OSError, TimeoutError) as exc:
        return ProbeResult(
            ok=False, error=f'Could not run the check from "{machine.name}": {exc}'[:500]
        )
    stdout = completed.stdout or ""
    text = stdout if isinstance(stdout, str) else stdout.decode("utf-8", "replace")
    return parse_output(check, text)
