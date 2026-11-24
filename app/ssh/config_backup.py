"""What a configuration backup reads on the machine, and how what arrives
is unpacked safely in debcontrol (see `app.services.config_backup`).

**Files.** One `tar` of `/etc` (on Proxmox VE that includes `/etc/pve`,
the cluster file system) and `/var/spool/cron` (every user's crontab),
streamed over SSH on standard output. Root reads everything through one
sudoers grant scoped to that exact command line (`TAR_GRANT`) — sudoers
matches the arguments, so the account can't make tar read anything else
or run `--to-command`. Without the grant tar runs as the account itself
and skips what it can't read; those paths are listed and the run counts
as *partial*. A machine without GNU tar (busybox) gets a plain `tar -c`.

**Packages.** A second, unprivileged command prints the installed
packages in forms that can be fed back (`dpkg --get-selections`,
`apt-mark showmanual`, `rpm -qa`, `pacman -Qqe`, `apk` world, snaps,
flatpaks) and the account's own crontab; they land in `_debcontrol/`.

**Unpacking.** The archive comes from a machine that could be
compromised, so it is unpacked with tarfile's `data` filter (no absolute
paths, no `..`, no links pointing outside, no device files, no setuid
bits), capped in size and member count, and every file is made readable
to debcontrol. The original owner, group and mode of each entry are kept
in `_debcontrol/permissions.tsv`, since the unpacked copy belongs to
debcontrol's own account.
"""

from __future__ import annotations

import os
import shlex
import stat
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

# The directories backed up, relative to `/`.
PATHS: tuple[str, ...] = ("etc", "var/spool/cron")
# GNU tar's arguments — no `=`, `,` or `:`, which sudoers would need escaped.
TAR_ARGS = "-c -f - --ignore-failed-read --warning no-file-changed -C / " + " ".join(PATHS)
TAR_BINARIES: tuple[str, ...] = ("/usr/bin/tar", "/bin/tar")
# The sudoers entries (app.ssh.onboarding.SUDO_COMMANDS).
TAR_GRANTS: tuple[str, ...] = tuple(f"{binary} {TAR_ARGS}" for binary in TAR_BINARIES)

# Through sudo when the grant (or root) allows it, else as the account.
TAR_COMMAND = (
    f"for t in {' '.join(TAR_BINARIES)}; do "
    f'if [ -x "$t" ] && sudo -n -l "$t" {TAR_ARGS} >/dev/null 2>&1; then '
    f'sudo -n "$t" {TAR_ARGS}; exit $?; fi; done; '
    f"if tar --version 2>/dev/null | grep -q GNU; then tar {TAR_ARGS}; exit $?; fi; "
    "set -- etc; [ -d /var/spool/cron ] && set -- etc var/spool/cron; "
    'tar -c -f - -C / "$@"'
)

# Package lists and the account's own crontab, one `===NAME===` section each.
PACKAGES_COMMAND = (
    "export LC_ALL=C; "
    "if command -v dpkg >/dev/null 2>&1; then "
    "echo ===DPKG_SELECTIONS===; dpkg --get-selections 2>/dev/null; fi; "
    "if command -v apt-mark >/dev/null 2>&1; then "
    "echo ===APT_MANUAL===; apt-mark showmanual 2>/dev/null; fi; "
    "if command -v rpm >/dev/null 2>&1; then "
    "echo ===RPM===; rpm -qa --qf '%{NAME}\\n' 2>/dev/null | sort; fi; "
    "if command -v pacman >/dev/null 2>&1; then "
    "echo ===PACMAN===; pacman -Qqe 2>/dev/null; fi; "
    "if [ -r /etc/apk/world ]; then echo ===APK===; cat /etc/apk/world; fi; "
    "if command -v snap >/dev/null 2>&1; then "
    "echo ===SNAP===; snap list 2>/dev/null | awk 'NR>1 {print $1}'; fi; "
    "if command -v flatpak >/dev/null 2>&1; then "
    "echo ===FLATPAK===; flatpak list --app --columns=application 2>/dev/null; fi; "
    "echo ===CRONTAB===; crontab -l 2>/dev/null; "
    "echo ===WHOAMI===; id -un"
)

# Section -> file name under `_debcontrol/`.
PACKAGE_FILES: dict[str, str] = {
    "DPKG_SELECTIONS": "packages-dpkg-selections.txt",
    "APT_MANUAL": "packages-apt-manual.txt",
    "RPM": "packages-rpm.txt",
    "PACMAN": "packages-pacman.txt",
    "APK": "packages-apk-world.txt",
    "SNAP": "snaps.txt",
    "FLATPAK": "flatpaks.txt",
}
META_DIR = "_debcontrol"

README = """\
Configuration backup made by debcontrol.

etc/, var/spool/cron/  the machine's files as they were
permissions.tsv        each entry's original mode, owner and group
                       (the copy here belongs to debcontrol's account)
unreadable.txt         what could not be read (no root on the machine)

Reinstalling packages:
  Debian/Ubuntu  apt-mark showmanual list: xargs -a packages-apt-manual.txt apt-get install
                 or: dpkg --set-selections < packages-dpkg-selections.txt
                     && apt-get dselect-upgrade
  RHEL/Fedora    xargs -a packages-rpm.txt dnf install
  Arch           pacman -S --needed - < packages-pacman.txt
  Alpine         copy packages-apk-world.txt to /etc/apk/world, apk add
"""

# Unpacking limits: what a sane /etc + crontabs never comes near.
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 200_000
MAX_LISTED_UNREADABLE = 500


class ArchiveError(Exception):
    """The archive from the machine could not be used."""


def split_sections(raw: str) -> dict[str, str]:
    """`===NAME===` sections of `PACKAGES_COMMAND`'s output."""
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in raw.splitlines():
        if line.startswith("===") and line.endswith("===") and len(line) > 6:
            current = sections.setdefault(line[3:-3], [])
        elif current is not None:
            current.append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


def unreadable_paths(stderr: str) -> list[str]:
    """Paths tar reported it could not read ("Permission denied" and the
    like — not "No such file", a directory that just isn't there)."""
    paths: list[str] = []
    for line in stderr.splitlines():
        if not line.startswith("tar: ") or "No such file" in line:
            continue
        cut = line.rfind(": Cannot ")
        if cut <= 5:
            continue
        path = line[5:cut].removesuffix(": Warning")
        if path not in paths:
            paths.append(path)
    return paths


@dataclass
class Unpacked:
    file_count: int = 0
    size_bytes: int = 0
    permissions: list[str] = field(default_factory=list)


def _owner(member: tarfile.TarInfo) -> tuple[str, str]:
    return (member.uname or str(member.uid), member.gname or str(member.gid))


def _readable(member: tarfile.TarInfo, dest_path: str) -> tarfile.TarInfo | None:
    """tarfile's `data` filter, then owner read (and directory search)
    rights, so debcontrol's account can back up every file it unpacked."""
    filtered = tarfile.data_filter(member, dest_path)
    if filtered is None:
        return None
    if filtered.isdir():
        return filtered.replace(mode=(filtered.mode or 0) | 0o700, deep=False)
    if filtered.isreg():
        return filtered.replace(mode=(filtered.mode or 0) | 0o600, deep=False)
    return filtered


def unpack(archive: Path, dest: Path) -> Unpacked:
    """Unpack `archive` into `dest` (which must exist). Raises
    `ArchiveError` for something that isn't a usable tar."""
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ArchiveError("The archive is larger than the limit.")
    result = Unpacked()
    try:
        with tarfile.open(archive, mode="r:") as tar:
            members: list[tarfile.TarInfo] = []
            for member in tar:
                if len(members) >= MAX_MEMBERS:
                    raise ArchiveError("The archive has too many entries.")
                if member.name.split("/", 1)[0] == META_DIR:
                    continue
                members.append(member)
            for member in members:
                try:
                    tar.extract(member, dest, filter=_readable)
                except (tarfile.FilterError, OSError):
                    continue
                if member.isreg():
                    result.file_count += 1
                    result.size_bytes += member.size
                owner, group = _owner(member)
                kind = "d" if member.isdir() else "l" if member.issym() else "-"
                result.permissions.append(
                    f"{kind}{stat.S_IMODE(member.mode):04o}\t{owner}\t{group}\t/{member.name.lstrip('/')}"
                )
    except tarfile.TarError as exc:
        raise ArchiveError(f"Not a usable tar archive: {exc}") from exc
    return result


def write_meta(
    dest: Path,
    *,
    packages: dict[str, str],
    unpacked: Unpacked,
    unreadable: list[str],
) -> None:
    """The `_debcontrol/` folder: package lists, the account's crontab,
    original permissions, what could not be read, and a README."""
    meta = dest / META_DIR
    meta.mkdir(mode=0o700, exist_ok=True)
    for section, name in PACKAGE_FILES.items():
        text = packages.get(section)
        if text:
            (meta / name).write_text(text + "\n", encoding="utf-8")
    crontab = packages.get("CRONTAB")
    user = packages.get("WHOAMI", "").strip().splitlines()[:1]
    if crontab and user and user[0].replace("-", "").replace("_", "").replace(".", "").isalnum():
        (meta / f"crontab-{user[0]}.txt").write_text(crontab + "\n", encoding="utf-8")
    (meta / "permissions.tsv").write_text(
        "mode\towner\tgroup\tpath\n" + "\n".join(unpacked.permissions) + "\n",
        encoding="utf-8",
        errors="replace",
    )
    if unreadable:
        (meta / "unreadable.txt").write_text(
            "\n".join(unreadable) + "\n", encoding="utf-8", errors="replace"
        )
    (meta / "README.txt").write_text(README, encoding="utf-8")


def restore_command(home_relative: str) -> str:
    """Writes standard input to `~/<home_relative>` (directories created,
    mode 600) — a restored file never goes over the original; the account
    moves it into place itself."""
    target = shlex.quote(home_relative)
    return (
        'cd "$(getent passwd "$(id -un)" | cut -d: -f6)" && umask 077 && '
        f"mkdir -p \"$(dirname {target})\" && cat > {target} && echo \"$PWD\""
    )


def is_safe_member_path(path: str) -> bool:
    """A path inside a snapshot that may be asked for: absolute, no `..`,
    no control characters."""
    if not path.startswith("/") or len(path) > 4096:
        return False
    if any(ord(c) < 32 for c in path):
        return False
    return ".." not in path.split("/") and os.path.normpath(path) == path
