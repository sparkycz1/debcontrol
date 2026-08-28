"""Run the apt update/upgrade/autoremove/autoclean sequence on a machine.

Always the same shape: `apt-get update`, then the chosen upgrade strategy,
then `autoremove` and `autoclean` — the cleanup steps run unconditionally,
even if the upgrade step failed, since they're independently useful and
shouldn't be skipped just because the upgrade itself hit a problem.

Requires root — either the machine's configured username *is* root, or
(recommended) it has passwordless sudo for `apt-get` specifically. See the
wiki page "Managed Machine Requirements" for a sudoers example. `sudo -n`
(non-interactive) is used throughout: if sudo would need a password, the
command fails immediately with a clear error instead of hanging forever
waiting for input that can never arrive over a non-interactive SSH exec.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.db.models.machine import Machine
from app.db.models.machine_update_run import UpgradeStrategy
from app.ssh.client import open_connection

_SUDO_APT = "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -y -q"
# Never prompt on a config-file conflict — keep the admin's existing config.
# The standard safe default for unattended Debian upgrades.
_DPKG_NONINTERACTIVE_FLAGS = (
    "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
)
_UPGRADE_SUBCOMMAND = {
    UpgradeStrategy.DIST_UPGRADE: "dist-upgrade",
    UpgradeStrategy.FULL_UPGRADE: "full-upgrade",
}


def build_update_command(strategy: UpgradeStrategy) -> str:
    """Build the remote shell script for one update run.

    A brace group (`{ ...; }`) rather than separate exec calls, so `2>&1`
    at the end captures stdout+stderr from every step in one place, and so
    the cleanup steps can run unconditionally while still preserving the
    upgrade step's exit status as the overall result.
    """
    upgrade_subcommand = _UPGRADE_SUBCOMMAND[strategy]
    return (
        "{ "
        "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update -q; "
        'status=$?; '
        'if [ "$status" -eq 0 ]; then '
        f"{_SUDO_APT} {_DPKG_NONINTERACTIVE_FLAGS} {upgrade_subcommand}; "
        'status=$?; '
        "fi; "
        f"{_SUDO_APT} autoremove; "
        f"{_SUDO_APT} autoclean; "
        'exit "$status"; '
        "} 2>&1"
    )


@dataclass
class UpdateResult:
    exit_status: int
    output: str


async def run_system_update(
    machine: Machine,
    secret: str | None,
    strategy: UpgradeStrategy,
    connect_timeout_seconds: int,
    run_timeout_seconds: int,
) -> UpdateResult:
    """Connect (strict pinned host-key verification, as always) and run the
    update sequence. `connect_timeout_seconds` only bounds establishing the
    connection; `run_timeout_seconds` bounds the whole apt sequence, which
    can legitimately take much longer.
    """
    script = build_update_command(strategy)
    async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
        result = await conn.run(script, check=False, timeout=run_timeout_seconds)

    stdout = result.stdout or ""
    output = stdout if isinstance(stdout, str) else stdout.decode()
    exit_status = result.exit_status if result.exit_status is not None else -1
    return UpdateResult(exit_status=exit_status, output=output)
