from __future__ import annotations

from app.ssh.power import PowerAction, build_power_command


def test_build_power_command_reboot():
    command = build_power_command(PowerAction.REBOOT)

    assert command == "(sudo -n shutdown -r now 2>/dev/null || shutdown -r now)"


def test_build_power_command_shutdown():
    command = build_power_command(PowerAction.SHUTDOWN)

    assert command == "(sudo -n shutdown -h now 2>/dev/null || shutdown -h now)"


def test_build_power_command_falls_back_when_already_root():
    """The whole point of the fallback: an account with no sudo grant at
    all (or none possible — a locked/no-password root account) still gets
    the real command run directly once `sudo -n` fails."""
    command = build_power_command(PowerAction.REBOOT)

    sudo_attempt, _, fallback = command.strip("()").partition(" || ")
    assert sudo_attempt == "sudo -n shutdown -r now 2>/dev/null"
    assert fallback == "shutdown -r now"
