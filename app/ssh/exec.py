"""One-shot remote command execution — run a single command, capture its
output and exit status, disconnect.

This is deliberately *not* the interactive terminal machinery
(`app.ssh.client.open_shell_session` + `app.web.routes.terminal_ws`). That
one allocates a PTY and relays a byte stream for the lifetime of a
WebSocket; this one is a plain `exec` channel with a request/response
shape, which is what the AI assistant's `run_ssh_command` tool needs: one
command in, exit status and captured output out, nothing to relay and
nothing to keep open.

Its closest sibling is `app.ssh.client.test_connection` (`open_connection`
plus a single `conn.run(...)`) — the same connection handling, the same
strict pinned host-key verification, just with a caller-supplied command
and both timeouts made explicit.

**Nothing in this module decides whether a command is allowed to run.**
Reaching here means an operator with `action.terminal` has already clicked
Confirm on the literal command text (see `app.web.routes.ai`), exactly as
if they had typed it into the browser terminal themselves. The command is
sent to the remote shell as-is; there is no escaping, filtering, or
allowlisting, because there is no meaningful way to sanitize "arbitrary
shell command" and pretending otherwise would be worse than being explicit
about it.
"""

from __future__ import annotations

from dataclasses import dataclass

import asyncssh

from app.db.models.machine import Machine
from app.ssh.client import open_connection
from app.ssh.exceptions import SSHConnectionError

# Captured output is fed back to an LLM and stored in a chat message; a
# command that dumps a huge file shouldn't blow up either. Keep the tail,
# where errors and summaries land — same convention as
# `app.tasks.jobs._truncate_output` uses for apt runs.
MAX_OUTPUT_CHARS = 20_000


@dataclass(frozen=True)
class CommandResult:
    exit_status: int
    output: str


def _truncate(output: str) -> str:
    if len(output) <= MAX_OUTPUT_CHARS:
        return output
    return "[... output truncated ...]\n" + output[-MAX_OUTPUT_CHARS:]


async def run_command(
    machine: Machine,
    secret: str | None,
    command: str,
    connect_timeout_seconds: int,
    run_timeout_seconds: int,
) -> CommandResult:
    """Connect (strict pinned host-key verification, as always), run one
    command, and return its exit status and combined stdout+stderr.

    `check=False`: a non-zero exit status is a *result* to report back, not
    an exception — "the command failed and here's why" is exactly what the
    person who confirmed it wants to see. `stderr=asyncssh.STDOUT` merges
    the two streams so the output reads in the order it was produced, the
    same way it would in the interactive terminal.
    """
    try:
        async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
            result = await conn.run(
                command, check=False, timeout=run_timeout_seconds, stderr=asyncssh.STDOUT
            )
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(f"Command failed on {machine.name}: {exc}") from exc

    stdout = result.stdout
    if stdout is None:
        text = ""
    else:
        text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")

    # AsyncSSH reports `None` for a process killed by a signal rather than
    # exiting normally — surface that as a distinct non-zero status instead
    # of pretending it succeeded.
    exit_status = result.exit_status if isinstance(result.exit_status, int) else -1
    return CommandResult(exit_status=exit_status, output=_truncate(text))
