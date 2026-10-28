"""Run a long shell script on a machine so that it does not depend on
debcontrol — the mechanism `app.ssh.detached_updates` uses for apt
updates, for any script (Docker updates, stack deployments, image scans,
restic backups).

The script is started with `setsid nohup` in a session of its own,
writing its output to a log file and its exit status to a status file
next to it, under `~/.local/state/debcontrol/<area>/` of the account
debcontrol connects as. The SSH session only starts it, then reads the
log every few seconds (`follow`). When debcontrol goes away — its worker
restarts, or the machine it runs on is the one whose containers are being
replaced — the script carries on; when debcontrol comes back it reads the
same files and finds out how the job ended
(`app.tasks.docker_jobs._resume_docker_job`). The files are removed once
the result is recorded.

The script itself is sent on the job's standard input and kept in a file
of the job (`<job>.sh`, mode 600 like everything there), never on a
command line: it may carry secrets (a restic password, a Git token), and
a command line is visible to every user of the machine in `ps`.

Each job is named after its row's id, so starting the same job twice
starts it once (`set -C`, the log file is created exclusively), and the
boot id written at start tells a process that is gone because the machine
restarted from one that is still running.

`app.ssh.detached_updates` keeps its own copy of these few commands: it
predates this module and its tests drive it through its own names.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import Awaitable, Callable

import asyncssh

from app.db.models.machine import Machine
from app.ssh.client import open_connection
from app.ssh.detached_updates import FollowResult, parse_poll_output
from app.ssh.exceptions import HostKeyError, SSHConnectionError
from app.ssh.shell import with_root_shim

__all__ = [
    "FollowResult",
    "build_cleanup_command",
    "build_poll_command",
    "build_start_command",
    "build_stop_command",
    "follow",
    "start",
]

_AREA_RE = re.compile(r"^[a-z]{1,16}$")
_JOB_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

_STARTED = "DC_JOB_STARTED"
_ALREADY = "DC_JOB_ALREADY_STARTED"

POLL_SECONDS = 3.0
RECONNECT_SECONDS = 10.0

# A job's output kept in memory while it is followed; a scan's JSON report
# can be large, anything beyond this is cut from the front.
MAX_FOLLOWED_BYTES = 64 * 1024 * 1024


def _job_file(area: str, job_id: str) -> str:
    if not _AREA_RE.match(area):
        raise ValueError(f"Not a job area: {area!r}")
    if not _JOB_ID_RE.match(job_id):
        raise ValueError(f"Not a job id: {job_id!r}")
    return f'f="${{HOME:-/tmp}}/.local/state/debcontrol/{area}/{job_id}"; '


def build_start_command(area: str, job_id: str) -> str:
    """Start the script read from standard input in the background and
    return at once. Prints `_STARTED`, or `_ALREADY` when this job was
    started before (its log exists)."""
    # The wrapper records the script's exit status once it has ended —
    # written to a temporary name and renamed, so a reader never sees half
    # of it, and only after the last line of output is in the log.
    #
    # The script itself runs in a process group of its own (`setsid`, when
    # the machine has it), its id kept in `<job>.cpid`: cancelling a job
    # (`build_stop_command`) signals that group — the script and whatever
    # it started — but not this wrapper, which still records how it ended.
    wrapper = (
        '$2 sh "$1.sh" & echo $! > "$1.cpid"; wait $!; '
        'echo $? > "$1.status.tmp" && mv "$1.status.tmp" "$1.status"'
    )
    return (
        "umask 077; "
        + _job_file(area, job_id)
        + 'mkdir -p "${f%/*}" || exit 1; '
        + f'if ! ( set -C; : > "$f.log" ) 2>/dev/null; then cat > /dev/null; echo {_ALREADY}; '
        + "exit 0; fi; "
        + 'cat > "$f.sh" || exit 1; '
        + 'cat /proc/sys/kernel/random/boot_id > "$f.boot" 2>/dev/null; '
        + "if command -v setsid >/dev/null 2>&1; then dc_detach=setsid; else dc_detach=; fi; "
        + f"nohup $dc_detach sh -c '{wrapper}' sh \"$f\" \"$dc_detach\" "
        + '>> "$f.log" 2>&1 < /dev/null & '
        + 'echo $! > "$f.pid"; '
        + f"echo {_STARTED}"
    )


def build_poll_command(area: str, job_id: str, offset: int) -> str:
    """One look at a job: a `DC_JOB_STATE <state> [exit status]` line, then
    the log from byte `offset` on (see `detached_updates.parse_poll_output`).

    Whether the process is alive is checked *before* the status file, so a
    job that ends between the two reads as finished, never as lost."""
    return (
        _job_file(area, job_id)
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


def build_stop_command(area: str, job_id: str) -> str:
    """Ask a running job to stop: SIGTERM to the script's process group
    (its own process when the machine has no `setsid`, or the whole job of
    one started before 0.126.0, which kept no `.cpid`). The script's EXIT
    traps still run — each job script turns SIGTERM into a plain exit —
    so containers it stopped are started again."""
    return _job_file(area, job_id) + (
        'p="$(cat "$f.cpid" 2>/dev/null)"; [ -n "$p" ] || p="$(cat "$f.pid" 2>/dev/null)"; '
        'case "$p" in ""|*[!0-9]*) exit 0;; esac; '
        # dash's kill takes no "--"; bash's and busybox's take either form.
        'kill -TERM "-$p" 2>/dev/null || kill -TERM -- "-$p" 2>/dev/null '
        '|| kill -TERM "$p" 2>/dev/null; exit 0'
    )


def build_cleanup_command(area: str, job_id: str) -> str:
    return _job_file(area, job_id) + (
        'rm -f "$f.log" "$f.sh" "$f.status" "$f.status.tmp" "$f.pid" "$f.cpid" "$f.boot"'
    )


async def start(
    machine: Machine,
    secret: str | None,
    area: str,
    job_id: str,
    script: str,
    connect_timeout_seconds: int,
) -> bool:
    """Start `script` as job `job_id`. True = started now, False = it had
    been started before. Raises `SSHConnectionError` when it could not be
    started. The script runs with the root shim (`app.ssh.shell`) in
    front, like every other command debcontrol runs."""
    command = build_start_command(area, job_id)
    try:
        async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
            result = await conn.run(
                command,
                input=with_root_shim(script),
                check=False,
                timeout=connect_timeout_seconds + 30,
            )
    except (asyncssh.Error, OSError) as exc:
        raise SSHConnectionError(f"Could not start the job: {exc}") from exc
    stdout = result.stdout or ""
    text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
    if _ALREADY in text:
        return False
    if _STARTED in text:
        return True
    detail = (text or str(result.stderr or "")).strip()[-300:]
    raise SSHConnectionError(f"Could not start the job on the machine: {detail or 'no answer'}")


async def follow(
    machine: Machine,
    secret: str | None,
    area: str,
    job_id: str,
    connect_timeout_seconds: int,
    timeout_seconds: float,
    *,
    on_output: Callable[[str], Awaitable[None]] | None = None,
    stop_requested: Callable[[], Awaitable[bool]] | None = None,
    poll_seconds: float = POLL_SECONDS,
    reconnect_seconds: float = RECONNECT_SECONDS,
) -> FollowResult:
    """Read the job's log until it ends or `timeout_seconds` pass — see
    `detached_updates.follow`, which this mirrors: a dropped connection is
    retried until the time is up, at least one look is always taken, and a
    changed host key is never retried.

    `stop_requested` is asked on every look while the job runs; once it
    says yes the job is signalled to stop (`build_stop_command`, once) and
    followed on until it has ended (`FollowResult.stopped`)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(timeout_seconds, 0)
    received = bytearray()
    # Bytes dropped from the front of `received` (`MAX_FOLLOWED_BYTES`);
    # the machine's log offset is `dropped + len(received)`.
    dropped = 0
    state: str | None = None
    last_error: str | None = None
    stopped = False
    first = True
    while first or loop.time() < deadline:
        first = False
        try:
            async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
                while True:
                    result = await conn.run(
                        build_poll_command(area, job_id, dropped + len(received)),
                        check=False,
                        encoding=None,
                        timeout=connect_timeout_seconds + 120,
                    )
                    raw = result.stdout or b""
                    poll = parse_poll_output(raw if isinstance(raw, bytes) else raw.encode())
                    state = poll.state
                    if poll.new_output:
                        received += poll.new_output
                        if len(received) > MAX_FOLLOWED_BYTES:
                            cut = len(received) - MAX_FOLLOWED_BYTES
                            del received[:cut]
                            dropped += cut
                        if on_output is not None:
                            await on_output(received.decode(errors="replace"))
                    if poll.state != "running":
                        output = received.decode(errors="replace")
                        if poll.state == "finished":
                            with contextlib.suppress(asyncssh.Error, OSError):
                                await conn.run(build_cleanup_command(area, job_id), check=False)
                        return FollowResult(
                            poll.state, poll.exit_status, output, stopped=stopped
                        )
                    if loop.time() >= deadline:
                        return FollowResult(
                            "timeout", None, received.decode(errors="replace"), stopped=stopped
                        )
                    if not stopped and stop_requested is not None and await stop_requested():
                        await conn.run(
                            build_stop_command(area, job_id),
                            check=False,
                            timeout=connect_timeout_seconds + 30,
                        )
                        stopped = True
                        continue
                    await asyncio.sleep(poll_seconds)
        except HostKeyError:
            raise
        except (SSHConnectionError, asyncssh.Error, OSError, TimeoutError, ValueError) as exc:
            last_error = str(exc) or type(exc).__name__
        if loop.time() >= deadline:
            break
        await asyncio.sleep(min(reconnect_seconds, max(deadline - loop.time(), 0)))
    if state == "running":
        return FollowResult(
            "timeout", None, received.decode(errors="replace"), last_error, stopped=stopped
        )
    return FollowResult(
        "unreachable", None, received.decode(errors="replace"), last_error, stopped=stopped
    )
