from __future__ import annotations

from app.ssh.power import PowerAction, build_power_command


def test_build_power_command_reboot():
    command = build_power_command(PowerAction.REBOOT)

    assert command == "sudo -n shutdown -r now"


def test_build_power_command_shutdown():
    command = build_power_command(PowerAction.SHUTDOWN)

    assert command == "sudo -n shutdown -h now"
