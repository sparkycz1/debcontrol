from __future__ import annotations

from app.ssh.readiness import READINESS_COMMAND, missing_requirements, parse_readiness_output


def _raw(
    ncurses: str = "ok",
    apt: str = "ok",
    shutdown: str = "ok",
    dmidecode: str = "ok",
    fs_present: str = "no",
    fs_sudo: str = "ok",
) -> str:
    return (
        f"===NCURSES_TERM===\n{ncurses}\n"
        f"===APT_SUDO===\n{apt}\n"
        f"===SHUTDOWN_SUDO===\n{shutdown}\n"
        f"===DMIDECODE_SUDO===\n{dmidecode}\n"
        f"===FLATPAK_SNAP_PRESENT===\n{fs_present}\n"
        f"===FLATPAK_SNAP_SUDO===\n{fs_sudo}\n"
    )


def test_parse_readiness_output_all_ok():
    result = parse_readiness_output(_raw())

    assert result["ncurses_term_installed"] is True
    assert result["apt_sudo_ok"] is True
    assert result["shutdown_sudo_ok"] is True
    assert result["dmidecode_sudo_ok"] is True
    assert result["flatpak_or_snap_present"] is False
    assert missing_requirements(result) == []


def test_parse_readiness_output_missing_things():
    result = parse_readiness_output(_raw(ncurses="missing", dmidecode="missing"))

    missing = missing_requirements(result)
    assert any("dmidecode" in m for m in missing)
    assert any("ncurses-term" in m for m in missing)
    assert not any("apt-get" in m for m in missing)


def test_parse_readiness_output_empty_string_reads_as_all_missing():
    result = parse_readiness_output("")

    assert result["ncurses_term_installed"] is False
    assert result["apt_sudo_ok"] is False
    assert len(missing_requirements(result)) == 4


def test_flatpak_snap_sudo_only_reported_when_present():
    # flatpak/snap not present at all — even though its own sudo probe
    # would technically read "missing" too (no command means the `if`
    # blocks never ran and `ok` stays 1... but even if it read as missing,
    # this must not show up when the package manager isn't there).
    result = parse_readiness_output(_raw(fs_present="no", fs_sudo="missing"))

    assert not any("flatpak" in m for m in missing_requirements(result))


def test_flatpak_snap_sudo_reported_when_present_and_missing():
    result = parse_readiness_output(_raw(fs_present="yes", fs_sudo="missing"))

    assert any("flatpak" in m for m in missing_requirements(result))


def test_flatpak_snap_sudo_not_reported_when_present_and_ok():
    result = parse_readiness_output(_raw(fs_present="yes", fs_sudo="ok"))

    assert not any("flatpak" in m for m in missing_requirements(result))


def test_readiness_command_skips_sudo_probes_when_already_root():
    """A machine already connected as root must never be told it's missing
    a sudo grant it has no way to need (or, on a locked/no-password root
    account, no way to even authenticate for) — see the module docstring.
    Every sudo-gated probe is short-circuited to "ok" once `id -u` is 0."""
    command = READINESS_COMMAND

    assert 'is_root=0; [ "$(id -u)" = "0" ] && is_root=1;' in command
    for probe in ("apt-get --version", "shutdown --help", "dmidecode -t 17"):
        assert f'[ "$is_root" = 1 ] && echo ok || (sudo -n {probe}' in command
    # The flatpak/snap sudo probe loop is skipped outright when already root.
    assert 'if [ "$is_root" != 1 ]; then' in command
