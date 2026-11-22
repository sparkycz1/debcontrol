"""Top processes on a managed machine, read on demand: the Overview's CPU
and memory cards open the list, refreshed every few seconds only while it
is open (`app.tasks.jobs._list_machine_processes`, on a worker so the SSH
connection is reused).

CPU use is measured, not `ps`'s lifetime average: two snapshots of every
process's CPU ticks (`/proc/<pid>/stat`) one second apart, the difference
worked out on the machine, so only the top rows travel back. 100% is one
fully busy core, as in `top`.

Command lines can hold secrets (`mysql -pPassword`), so they are only
read at all when the viewer may also open a terminal on the machine
(`include_args`); everyone else sees the process name.

`signal_command` sends TERM or KILL — but only to the process that was
shown: the PID together with its start time (`/proc/<pid>/stat` field 22),
so a PID reused in the meantime is never hit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

import asyncssh

from app.db.models.machine import Machine
from app.ssh.client import open_connection
from app.ssh.exceptions import SSHConnectionError
from app.ssh.pool import machine_connection
from app.ssh.shell import output_text, with_root_shim

SortKey = Literal["cpu", "memory"]
SORT_KEYS: tuple[SortKey, ...] = ("cpu", "memory")
SIGNALS = ("TERM", "KILL")
DEFAULT_LIMIT = 25
MAX_LIMIT = 100
_ARGS_LIMIT = 500
_DETAIL_ARGS_LIMIT = 4000

# CPU ticks of every process: "pid ticks". The name in field 2 can hold
# spaces and parentheses, so everything up to the last ") " is cut first;
# utime and stime are then the 12th and 13th field.
_SNAPSHOT = (
    "cat /proc/[0-9]*/stat 2>/dev/null | awk '{l = $0; sub(/^.*\\) /, \"\", l); "
    "n = split(l, a, \" \"); if (n >= 13) print $1, a[12] + a[13]}'"
)


def list_command(sort: SortKey, limit: int, *, include_args: bool) -> str:
    limit = max(1, min(int(limit), MAX_LIMIT))
    if sort == "memory":
        pick = (
            f"ps -e -o pid=,rss= --sort=-rss 2>/dev/null | head -n {limit} "
            "| awk 'NR==FNR {d[$1]=$2; next} {print $1, ($1 in d) ? d[$1] : 0}' \"$T/d\" - "
            '> "$T/top"'
        )
    else:
        pick = f'sort -k2,2nr -k1,1n "$T/d" | head -n {limit} > "$T/top"'
    args = (
        'echo @@ARGS; for p in $(cut -d" " -f1 "$T/top"); do '
        'printf "%s " "$p"; tr "\\000" " " < "/proc/$p/cmdline" 2>/dev/null '
        f"| cut -c1-{_ARGS_LIMIT}; "
        "echo; done; "
        if include_args
        else ""
    )
    return (
        'T="$(mktemp -d 2>/dev/null)" || exit 0; '
        "U1=\"$(cut -d' ' -f1 /proc/uptime)\"; "
        f'{_SNAPSHOT} > "$T/a"; sleep 1; {_SNAPSHOT} > "$T/b"; '
        "U2=\"$(cut -d' ' -f1 /proc/uptime)\"; "
        'awk \'NR==FNR {t[$1]=$2; next} {print $1, ($1 in t) ? $2 - t[$1] : 0}\' "$T/a" "$T/b" '
        '> "$T/d"; '
        f"{pick}; "
        'echo "@@META $(getconf CLK_TCK 2>/dev/null) $U1 $U2 '
        "$(nproc 2>/dev/null) $(awk '/^MemTotal:/ {print $2}' /proc/meminfo) "
        '$(wc -l < "$T/b")"; '
        'echo @@TOP; cat "$T/top"; '
        'P="$(cut -d" " -f1 "$T/top" | paste -sd, -)"; '
        'echo @@PS; [ -n "$P" ] && ps -o pid=,ppid=,user:32=,rss=,stat=,etimes=,nlwp=,comm= '
        '-p "$P" 2>/dev/null; '
        f"{args}"
        'rm -rf "$T"'
    )


@dataclass
class ProcessRow:
    pid: int
    cpu_percent: float | None
    memory_bytes: int | None
    memory_percent: float | None
    user: str | None = None
    ppid: int | None = None
    state: str | None = None
    elapsed_seconds: int | None = None
    threads: int | None = None
    name: str | None = None
    # Only when the viewer may see command lines.
    args: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class ProcessList:
    sort: SortKey
    rows: list[ProcessRow] = field(default_factory=list)
    total: int | None = None
    cores: int | None = None
    memory_total_bytes: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "sort": self.sort,
            "total": self.total,
            "cores": self.cores,
            "memory_total_bytes": self.memory_total_bytes,
            "processes": [row.as_dict() for row in self.rows],
        }


def _int(value: str) -> int | None:
    return int(value) if value.isdecimal() else None


def _sections(raw: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in raw.splitlines():
        if line.startswith("@@"):
            tag, _, rest = line[2:].partition(" ")
            current = sections.setdefault(tag, [])
            if rest:
                current.append(rest)
            continue
        if current is not None and line.strip():
            current.append(line)
    return sections


def parse_list(raw: str, sort: SortKey) -> ProcessList:
    """Read `list_command`'s output. Pure function, no I/O."""
    sections = _sections(raw)
    result = ProcessList(sort=sort)
    meta = (sections.get("META") or [""])[0].split()
    ticks_per_second = elapsed = None
    if len(meta) == 6:
        ticks_per_second = _int(meta[0])
        try:
            elapsed = float(meta[2]) - float(meta[1])
        except ValueError:
            elapsed = None
        result.cores = _int(meta[3])
        memory_kb = _int(meta[4])
        result.memory_total_bytes = memory_kb * 1024 if memory_kb else None
        result.total = _int(meta[5])

    order: list[int] = []
    cpu: dict[int, float | None] = {}
    for line in sections.get("TOP", []):
        fields = line.split()
        if len(fields) != 2 or not fields[0].isdecimal():
            continue
        pid = int(fields[0])
        order.append(pid)
        delta = _int(fields[1])
        cpu[pid] = (
            round(max(delta, 0) / ticks_per_second / elapsed * 100, 1)
            if delta is not None and ticks_per_second and elapsed and elapsed > 0
            else None
        )

    details: dict[int, list[str]] = {}
    for line in sections.get("PS", []):
        fields = line.split(None, 7)
        if len(fields) == 8 and fields[0].isdecimal():
            details[int(fields[0])] = fields
    args: dict[int, str] = {}
    for line in sections.get("ARGS", []):
        pid_text, _, text = line.partition(" ")
        if pid_text.isdecimal():
            args[int(pid_text)] = text.strip()

    for pid in order:
        info = details.get(pid)
        if info is None:
            continue  # Gone between the snapshot and `ps`.
        rss_kb = _int(info[3])
        memory = rss_kb * 1024 if rss_kb is not None else None
        result.rows.append(
            ProcessRow(
                pid=pid,
                cpu_percent=cpu.get(pid),
                memory_bytes=memory,
                memory_percent=(
                    round(memory / result.memory_total_bytes * 100, 1)
                    if memory is not None and result.memory_total_bytes
                    else None
                ),
                ppid=_int(info[1]),
                user=info[2],
                state=info[4],
                elapsed_seconds=_int(info[5]),
                threads=_int(info[6]),
                name=info[7].strip(),
                args=args.get(pid) if sections.get("ARGS") is not None else None,
            )
        )
    return result


# --- one process -------------------------------------------------------------


def detail_command(pid: int, *, include_args: bool) -> str:
    p = int(pid)
    args = (
        f'echo @@ARGS; tr "\\000" " " < /proc/{p}/cmdline 2>/dev/null '
        f"| cut -c1-{_DETAIL_ARGS_LIMIT}; echo; "
        if include_args
        else ""
    )
    return (
        f"[ -r /proc/{p}/stat ] || {{ echo @@GONE; exit 0; }}; "
        f"echo @@STAT; cat /proc/{p}/stat 2>/dev/null; "
        "echo @@STATUS; "
        "grep -E '^(Name|State|PPid|Uid|Threads|VmRSS|VmSwap|voluntary_ctxt_switches"
        f"|nonvoluntary_ctxt_switches):' /proc/{p}/status 2>/dev/null; "
        f"echo @@USER; ps -o user:32= -p {p} 2>/dev/null; "
        f"echo @@CGROUP; cat /proc/{p}/cgroup 2>/dev/null; "
        "echo \"@@CLOCK $(getconf CLK_TCK 2>/dev/null) $(cut -d' ' -f1 /proc/uptime) "
        "$(awk '/^btime/ {print $2}' /proc/stat)\"; "
        f"{args}"
        "true"
    )


_UNIT_RE = re.compile(r"/([^/]+\.service)$")
_SCOPE_RE = re.compile(r"/docker-([0-9a-f]{12,64})\.scope$|/docker/([0-9a-f]{12,64})$")
_LXC_RE = re.compile(r"^/lxc(?:\.payload)?[./](\d+)(?:/|$)")


def owner_of(cgroup_paths: list[str]) -> dict[str, str] | None:
    """Which systemd service, Docker container or Proxmox container a
    process belongs to, from its `/proc/<pid>/cgroup` lines (or just their
    paths)."""
    cgroup_paths = [line.split(":", 2)[-1] for line in cgroup_paths]
    for path in cgroup_paths:
        match = _SCOPE_RE.search(path)
        if match:
            return {"kind": "container", "id": (match.group(1) or match.group(2))[:12]}
        match = _LXC_RE.match(path)
        if match:
            return {"kind": "lxc", "id": match.group(1)}
    for path in cgroup_paths:
        match = _UNIT_RE.search(path)
        if match:
            return {"kind": "service", "id": match.group(1)}
    return None


def _stat_fields(stat_line: str) -> tuple[str | None, list[str]]:
    """(name, fields after the name) — fields[0] is the state (field 3)."""
    start, end = stat_line.find("("), stat_line.rfind(")")
    if start < 0 or end < start:
        return None, []
    return stat_line[start + 1 : end], stat_line[end + 1 :].split()


def parse_detail(raw: str, pid: int) -> dict[str, Any] | None:
    """Read `detail_command`'s output; None when the process is gone."""
    sections = _sections(raw)
    if "GONE" in sections or not sections.get("STAT"):
        return None
    name, fields = _stat_fields(sections["STAT"][0])
    if len(fields) < 20:
        return None
    clock = (sections.get("CLOCK") or [""])[0].split()
    ticks = _int(clock[0]) if clock else None
    start_ticks = _int(fields[19])
    boot = _int(clock[2]) if len(clock) == 3 else None
    try:
        uptime = float(clock[1]) if len(clock) >= 2 else None
    except ValueError:
        uptime = None
    started_at = (
        boot + start_ticks // ticks if boot and start_ticks is not None and ticks else None
    )
    cpu_seconds = None
    utime, stime = _int(fields[11]), _int(fields[12])
    if utime is not None and stime is not None and ticks:
        cpu_seconds = round((utime + stime) / ticks, 2)
    status: dict[str, str] = {}
    for line in sections.get("STATUS", []):
        key, _, value = line.partition(":")
        status[key.strip()] = value.strip()

    def kb(key: str) -> int | None:
        value = status.get(key, "").split()
        return int(value[0]) * 1024 if value and value[0].isdecimal() else None

    args_lines = sections.get("ARGS")
    return {
        "pid": pid,
        "name": status.get("Name") or name,
        "state": status.get("State") or fields[0],
        "ppid": _int(status.get("PPid", "")),
        "user": (sections.get("USER") or [""])[0] or None,
        "uid": _int((status.get("Uid", "").split() or [""])[0]),
        "threads": _int(status.get("Threads", "")),
        "memory_bytes": kb("VmRSS"),
        "swap_bytes": kb("VmSwap"),
        "cpu_seconds": cpu_seconds,
        "started_at": started_at,
        "elapsed_seconds": (
            int(uptime - start_ticks / ticks)
            if uptime is not None and start_ticks is not None and ticks
            else None
        ),
        "context_switches": _int(status.get("voluntary_ctxt_switches", "")),
        "owner": owner_of(sections.get("CGROUP", [])),
        # The identity a signal must match (see `signal_command`).
        "start_ticks": start_ticks,
        "args": " ".join(args_lines).strip() if args_lines is not None else None,
    }


# --- signals -----------------------------------------------------------------


def signal_command(pid: int, start_ticks: int, signal: str) -> str:
    if signal not in SIGNALS:
        raise ValueError(f"Unsupported signal {signal!r}.")
    p, want = int(pid), int(start_ticks)
    if p <= 1:
        raise ValueError("Refusing to signal PID 0 or 1.")
    return (
        f"S=\"$(cat /proc/{p}/stat 2>/dev/null | awk '{{l = $0; sub(/^.*\\) /, \"\", l); "
        "split(l, a, \" \"); print a[20]}')\"; "
        f'[ "$S" = "{want}" ] || {{ echo @@GONE; exit 0; }}; '
        f"if kill -s {signal} {p} 2>/dev/null; then echo @@OK; "
        f"elif sudo -n kill -s {signal} {p} 2>/dev/null; then echo @@OK; "
        "else echo @@DENIED; fi"
    )


SignalOutcome = Literal["ok", "gone", "denied", "error"]


def parse_signal(raw: str) -> SignalOutcome:
    for line in raw.splitlines():
        tag = line.strip()
        if tag == "@@OK":
            return "ok"
        if tag == "@@GONE":
            return "gone"
        if tag == "@@DENIED":
            return "denied"
    return "error"


# --- running them --------------------------------------------------------------


async def read_processes(
    machine: Machine,
    secret: str | None,
    timeout_seconds: int,
    sort: SortKey,
    limit: int,
    *,
    include_args: bool,
) -> ProcessList:
    command = list_command(sort, limit, include_args=include_args)
    async with machine_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(command, check=False, timeout=timeout_seconds + 10)
    return parse_list(output_text(result), sort)


async def read_process(
    machine: Machine, secret: str | None, timeout_seconds: int, pid: int, *, include_args: bool
) -> dict[str, Any] | None:
    async with machine_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(
            detail_command(pid, include_args=include_args), check=False, timeout=timeout_seconds
        )
    return parse_detail(output_text(result), pid)


async def send_signal(
    machine: Machine,
    secret: str | None,
    timeout_seconds: int,
    pid: int,
    start_ticks: int,
    signal: str,
) -> SignalOutcome:
    """An action, not a reading: its own connection, never a reused one."""
    command = with_root_shim(signal_command(pid, start_ticks, signal))
    try:
        async with await open_connection(machine, secret, timeout_seconds) as conn:
            result = await conn.run(command, check=False, timeout=timeout_seconds)
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(f"Could not signal a process on {machine.name}: {exc}") from exc
    return parse_signal(output_text(result))
