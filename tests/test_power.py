from __future__ import annotations

import pytest

from app.ssh.power import PowerAction, build_power_command


@pytest.mark.parametrize(
    ("action", "flag"), [(PowerAction.REBOOT, "-r"), (PowerAction.SHUTDOWN, "-h")]
)
def test_build_power_command_tries_sudo_then_runs_it_directly(
    action: PowerAction, flag: str
) -> None:
    """An account with no sudo grant at all (or root itself) still gets the
    real command run once `sudo -n` fails."""
    assert build_power_command(action) == (
        f"(sudo -n shutdown {flag} now 2>/dev/null || shutdown {flag} now)"
    )
