"""Shell glue shared by every command this app runs on a managed machine.

**No `sudo` when the account already is root.** Commands here reach for
root rights with `sudo -n <cmd>` (falling back to the plain command) or
ask first with `sudo -n -l <path>`, so an unprivileged account with a
scoped sudoers grant works. Connected *as* root, `sudo` still "works" —
but every call writes its own `sudo: root : ... COMMAND=...` line plus a
`pam_unix(sudo:session)` open/close pair to the machine's journal, which
on a monitoring cadence buries the journal in debcontrol's own noise.

`ROOT_SUDO_SHIM`, prepended to a command (`with_root_shim`), defines a
`sudo` shell *function* only when `id -u` is 0: it drops sudo's own
options, answers `-l <path>` ("am I allowed to run this?") with "yes, if it
exists", and runs everything else directly through `env` (so a
`sudo VAR=value cmd` form keeps working). A non-root account never sees
the function — the real `sudo` binary runs exactly as before. Functions
are inherited by subshells, `$(...)` and pipelines, so one definition at
the top covers the whole script.
"""

from __future__ import annotations

from typing import Any

import asyncssh

ROOT_SUDO_SHIM = (
    'if [ "$(id -u)" = 0 ]; then sudo() { '
    "_dc_list=; "
    "while [ $# -gt 0 ]; do case \"$1\" in "
    "-l) _dc_list=1; shift;; "
    "--) shift; break;; "
    "-*) shift;; "
    "*) break;; "
    "esac; done; "
    'if [ -n "$_dc_list" ]; then [ $# -eq 0 ] || command -v "$1" >/dev/null 2>&1; return; fi; '
    'env "$@"; '
    "}; fi; "
)


def with_root_shim(command: str) -> str:
    """`command`, with `sudo` turned into a no-op wrapper when run as root."""
    return ROOT_SUDO_SHIM + command


async def run(
    conn: asyncssh.SSHClientConnection, command: str, **kwargs: Any
) -> asyncssh.SSHCompletedProcess:
    """`conn.run(command, ...)` with `ROOT_SUDO_SHIM` in front — the one way
    this app's modules run a remote command that may use `sudo`."""
    return await conn.run(with_root_shim(command), **kwargs)


def output_text(result: asyncssh.SSHCompletedProcess) -> str:
    """A completed command's stdout as text (`""` when there was none)."""
    stdout = result.stdout or ""
    return stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
