"""Run an update on a machine so that it does not depend on debcontrol.

`app.ssh.updates.run_system_update` runs apt over the SSH session itself:
if debcontrol stops in the middle (its worker restarts, or the machine it
runs on is the one being updated and Docker restarts with it), the session
closes, the update is cut off or keeps going unseen, and the run is left
"running" with nobody to finish it.

Here the same script runs **detached** on the machine instead: started
with `setsid nohup` in a session of its own, writing its output to a log
file and its exit status to a status file next to it, under
`~/.local/state/debcontrol/updates/` of the account debcontrol connects
as. The SSH session only starts it, then reads the log every few seconds
(`follow`). When debcontrol goes away, the update carries on; when it
comes back, it reads the same files again and finds out how it ended
(`app.tasks.jobs._resume_machine_update`). The files are removed once the
result is recorded.

Each job is named after its update run's id, so starting the same run
twice starts it once (`set -C`, the log file is created exclusively), and
the boot id written at start tells a process that is gone because the
machine restarted from one that is still running.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

import asyncssh

from app.db.models.machine import Machine
from app.db.models.machine_update_run import UpgradeStrategy
from app.ssh.client import open_connection
from app.ssh.exceptions import HostKeyError, SSHConnectionError
from app.ssh.shell import with_root_shim
from app.ssh.updates import _upgrade_step, build_update_command

# Where the job's files live — the connecting account's own state
# directory, so no extra rights are needed and nobody else can read it.
_JOB_DIR = '"${HOME:-/tmp}/.local/state/debcontrol/updates"'
_JOB_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

_STARTED = "DC_JOB_STARTED"
_ALREADY = "DC_JOB_ALREADY_STARTED"
_STATE_PREFIX = b"DC_JOB_STATE "

# How often a followed job's log is read, and how long to wait before
# connecting again after the connection dropped.
POLL_SECONDS = 3.0
RECONNECT_SECONDS = 10.0

JobState = Literal["running", "finished", "lost", "missing"]


def _job_file(job_id: str) -> str:
    if not _JOB_ID_RE.match(job_id):
        raise ValueError(f"Not a job id: {job_id!r}")
    return f'f={_JOB_DIR}/{job_id}; '


def build_start_command(job_id: str, strategy: UpgradeStrategy) -> str:
    """Start the update script for `strategy` in the background and return
    at once. Prints `_STARTED`, or `_ALREADY` when this job was started
    before (its log exists)."""
    script = with_root_shim(build_update_command(strategy))
    # The wrapper records the script's exit status once it has ended —
    # written to a temporary name and renamed, so a reader never sees half
    # of it, and only after the last line of output is in the log.
    wrapper = 'sh -c "$1"; echo $? > "$2.status.tmp" && mv "$2.status.tmp" "$2.status"'
    return (
        "umask 077; "
        + _job_file(job_id)
        + 'mkdir -p "${f%/*}" || exit 1; '
        + f'if ! ( set -C; : > "$f.log" ) 2>/dev/null; then echo {_ALREADY}; exit 0; fi; '
        + 'cat /proc/sys/kernel/random/boot_id > "$f.boot" 2>/dev/null; '
        + "if command -v setsid >/dev/null 2>&1; then dc_detach=setsid; else dc_detach=; fi; "
        + f'nohup $dc_detach sh -c {shlex.quote(wrapper)} sh {shlex.quote(script)} "$f" '
        + '>> "$f.log" 2>&1 < /dev/null & '
        + 'echo $! > "$f.pid"; '
        + f"echo {_STARTED}"
    )


def build_poll_command(job_id: str, offset: int) -> str:
    """One look at a job: a `DC_JOB_STATE <state> [exit status]` line, then
    the log from byte `offset` on.

    Whether the process is alive is checked *before* the status file, so a
    job that ends between the two reads as finished, never as lost."""
    return (
        _job_file(job_id)
        + "dc_alive=0; "
        + 'if [ "$(cat "$f.boot" 2>/dev/null)" = '
        + '"$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" ] '
        + '&& kill -0 "$(cat "$f.pid" 2>/dev/null)" 2>/dev/null; then dc_alive=1; fi; '
        + 'if [ -f "$f.status" ]; then echo "DC_JOB_STATE finished $(cat "$f.status")"; '
        + 'elif [ ! -f "$f.log" ]; then echo "DC_JOB_STATE missing"; '
        + 'elif [ "$dc_alive" = 1 ]; then echo "DC_JOB_STATE running"; '
        + 'else echo "DC_JOB_STATE lost"; fi; '
        + f'tail -c +{int(offset) + 1} "$f.log" 2>/dev/null; exit 0'
    )


def build_cleanup_command(job_id: str) -> str:
    return _job_file(job_id) + 'rm -f "$f.log" "$f.status" "$f.status.tmp" "$f.pid" "$f.boot"'


@dataclass(frozen=True)
class Poll:
    state: JobState
    exit_status: int | None
    new_output: bytes


def parse_poll_output(raw: bytes) -> Poll:
    """Split `build_poll_command`'s output into the state line and the log."""
    head, _, rest = raw.partition(b"\n")
    if not head.startswith(_STATE_PREFIX):
        raise ValueError("Unexpected answer from the machine.")
    words = head[len(_STATE_PREFIX) :].decode(errors="replace").split()
    state = words[0] if words else ""
    if state not in ("running", "finished", "lost", "missing"):
        raise ValueError(f"Unexpected job state {state!r}.")
    exit_status: int | None = None
    if state == "finished":
        try:
            exit_status = int(words[1])
        except (IndexError, ValueError):
            exit_status = -1
    return Poll(state=state, exit_status=exit_status, new_output=rest)  # type: ignore[arg-type]


async def start(
    machine: Machine,
    secret: str | None,
    job_id: str,
    strategy: UpgradeStrategy,
    connect_timeout_seconds: int,
) -> bool:
    """Start the job. True = started now, False = it had been started
    before. Raises `SSHConnectionError` when it could not be started."""
    command = build_start_command(job_id, strategy)
    try:
        async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
            result = await conn.run(command, check=False, timeout=connect_timeout_seconds + 30)
    except (asyncssh.Error, OSError) as exc:
        raise SSHConnectionError(f"Could not start the update: {exc}") from exc
    stdout = result.stdout or ""
    text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
    if _ALREADY in text:
        return False
    if _STARTED in text:
        return True
    detail = (text or str(result.stderr or "")).strip()[-300:]
    raise SSHConnectionError(f"Could not start the update on the machine: {detail or 'no answer'}")


@dataclass(frozen=True)
class FollowResult:
    """How following a job ended. `state` is the job's last known state,
    or "unreachable" / "timeout" when debcontrol stopped looking first."""

    state: Literal["finished", "lost", "missing", "unreachable", "timeout"]
    exit_status: int | None
    output: str
    error: str | None = None
    # Whether debcontrol signalled the job to stop (a cancelled Docker job,
    # `app.ssh.detached_jobs.follow`).
    stopped: bool = False


async def follow(
    machine: Machine,
    secret: str | None,
    job_id: str,
    connect_timeout_seconds: int,
    timeout_seconds: float,
    *,
    on_output: Callable[[str], Awaitable[None]] | None = None,
    poll_seconds: float = POLL_SECONDS,
    reconnect_seconds: float = RECONNECT_SECONDS,
) -> FollowResult:
    """Read the job's log until it ends or `timeout_seconds` pass.

    A dropped connection (the machine restarting sshd during its own
    upgrade, a network blip) is not the end: it connects again until the
    time is up. At least one look is always taken, even with no time
    left, so a job that finished while nobody was watching is still read.
    `on_output` gets everything read so far, each time something new
    arrives."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(timeout_seconds, 0)
    received = bytearray()
    poll: Poll | None = None
    last_error: str | None = None
    first = True
    while first or loop.time() < deadline:
        first = False
        try:
            async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
                while True:
                    result = await conn.run(
                        build_poll_command(job_id, len(received)),
                        check=False,
                        encoding=None,
                        timeout=connect_timeout_seconds + 60,
                    )
                    raw = result.stdout or b""
                    poll = parse_poll_output(raw if isinstance(raw, bytes) else raw.encode())
                    if poll.new_output:
                        received += poll.new_output
                        if on_output is not None:
                            await on_output(received.decode(errors="replace"))
                    if poll.state != "running":
                        output = received.decode(errors="replace")
                        if poll.state == "finished":
                            # Left behind is harmless; the result is what matters.
                            with contextlib.suppress(asyncssh.Error, OSError):
                                await conn.run(build_cleanup_command(job_id), check=False)
                        return FollowResult(poll.state, poll.exit_status, output)
                    if loop.time() >= deadline:
                        return FollowResult("timeout", None, received.decode(errors="replace"))
                    await asyncio.sleep(poll_seconds)
        except HostKeyError:
            # Never retried: a changed key needs a person, not patience.
            raise
        except (SSHConnectionError, asyncssh.Error, OSError, TimeoutError, ValueError) as exc:
            last_error = str(exc) or type(exc).__name__
        if loop.time() >= deadline:
            break
        await asyncio.sleep(min(reconnect_seconds, max(deadline - loop.time(), 0)))
    if poll is not None and poll.state == "running":
        return FollowResult("timeout", None, received.decode(errors="replace"), last_error)
    return FollowResult("unreachable", None, received.decode(errors="replace"), last_error)


# --- Checking a machine whose update debcontrol lost track of ---------------

_AUDIT_MARKER = "===DC_DPKG_AUDIT==="
_SIM_MARKER = "===DC_UPGRADE_SIM==="


def build_verify_command(strategy: UpgradeStrategy) -> str:
    """Is the machine where the update would have left it? `dpkg --audit`
    (empty = nothing half-installed) and the same upgrade step simulated
    (no `Inst` line = nothing left for this strategy to do)."""
    return with_root_shim(
        "{ "
        f"echo {_AUDIT_MARKER}; dpkg --audit 2>&1; "
        f"echo {_SIM_MARKER}; {_upgrade_step(strategy, simulate=True)}; "
        "} 2>&1"
    )


@dataclass(frozen=True)
class Verification:
    ok: bool
    pending: int
    dpkg_problems: str
    detail: str


def parse_verify_output(raw: str, exit_status: int | None) -> Verification:
    audit, _, simulated = raw.partition(_SIM_MARKER)
    audit = audit.replace(_AUDIT_MARKER, "", 1).strip()
    pending = sum(1 for line in simulated.splitlines() if line.startswith("Inst "))
    simulated_ok = exit_status == 0 and _SIM_MARKER in raw
    ok = simulated_ok and not audit and pending == 0
    if not simulated_ok:
        detail = "Couldn't check what is left to upgrade: " + (
            simulated.strip()[-300:] or "no answer"
        )
    elif audit:
        detail = "dpkg reports half-installed packages: " + audit[:300]
    elif pending:
        detail = f"{pending} package{'s' if pending != 1 else ''} still to upgrade."
    else:
        detail = "Nothing left to upgrade and dpkg is consistent."
    return Verification(ok=ok, pending=pending, dpkg_problems=audit, detail=detail)


async def verify(
    machine: Machine,
    secret: str | None,
    strategy: UpgradeStrategy,
    connect_timeout_seconds: int,
) -> Verification:
    """Run `build_verify_command`. Raises `SSHConnectionError` when the
    machine can't be reached."""
    try:
        async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
            result = await conn.run(
                build_verify_command(strategy), check=False, timeout=connect_timeout_seconds + 300
            )
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(f"Could not check the machine: {exc}") from exc
    stdout = result.stdout or ""
    text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
    return parse_verify_output(text, result.exit_status)
