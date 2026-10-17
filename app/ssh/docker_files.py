"""Browsing, reading and changing files inside a container or a volume.

**A container**: listing and the small changes run inside it with
`docker exec` (so it must be running and have a shell — a "distroless"
image has none, and says so); reading and writing go through
`docker cp`, which needs neither and works on a stopped container too.

**A volume**: everything runs in a throwaway busybox container
(`docker_cli.BUSYBOX_IMAGE`) with the volume mounted at `/data` —
read-only for listing and reading. Nothing outside the volume is mounted,
and every path is kept inside `/data`.

Files travel as tar streams (`docker cp` speaks tar; so does busybox), so
a file keeps its owner and mode when it is edited. A file read for
display is limited to `MAX_EDIT_BYTES`, a download to
`MAX_DOWNLOAD_BYTES`; the limit is enforced on the machine (`head -c`),
not after the bytes arrived.

Paths are normalized (`normalize_path`) and quoted; a path that is not
absolute, or holds a newline or NUL, is refused before anything runs.
"""

from __future__ import annotations

import io
import posixpath
import tarfile
import time
from dataclasses import dataclass
from typing import Literal

from app.ssh.docker_cli import (
    BUSYBOX_IMAGE,
    HELPER_LABEL,
    DockerCommandError,
    is_container_name_valid,
    is_volume_name_valid,
    q,
)

TargetKind = Literal["container", "volume"]

MAX_ENTRIES = 2000
MAX_EDIT_BYTES = 1024 * 1024
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

_VOLUME_ROOT = "/data"

# Lists one directory: type|size|mtime|mode|user|group|name, one per entry.
_LIST_SCRIPT = (
    'cd -- "$1" 2>/dev/null || { echo @@DC_NODIR; exit 0; }; '
    "for f in .* *; do "
    'if [ "$f" = . ] || [ "$f" = .. ]; then continue; fi; '
    '[ -e "$f" ] || [ -L "$f" ] || continue; '
    "stat -c '%F|%s|%Y|%A|%U|%G|%n' -- \"$f\" 2>/dev/null; "
    f"done | head -n {MAX_ENTRIES}"
)


def normalize_path(path: str) -> str:
    """An absolute, normalized path; raises `DockerCommandError`."""
    if not path or "\0" in path or "\n" in path or "\r" in path or len(path) > 4096:
        raise DockerCommandError("Invalid path.")
    if not path.startswith("/"):
        path = "/" + path
    normalized = posixpath.normpath(path)
    # normpath keeps a leading "//".
    return "/" + normalized.lstrip("/")


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    name: str

    def __post_init__(self) -> None:
        valid = (
            is_container_name_valid(self.name)
            if self.kind == "container"
            else is_volume_name_valid(self.name)
        )
        if self.kind not in ("container", "volume") or not valid:
            raise DockerCommandError("Invalid container or volume.")

    def inside(self, path: str) -> str:
        """The path as the command sees it (under `/data` for a volume)."""
        normalized = normalize_path(path)
        if self.kind == "volume":
            return _VOLUME_ROOT if normalized == "/" else _VOLUME_ROOT + normalized
        return normalized

    def run(self, script: str, *args: str, writable: bool = False, stdin: bool = False) -> str:
        """`sh -c script sh args...` inside the container or the helper."""
        quoted_args = " ".join(q(arg) for arg in args)
        interactive = "-i " if stdin else ""
        if self.kind == "container":
            return f"$D exec {interactive}{q(self.name)} sh -c {q(script)} sh {quoted_args}"
        mode = "" if writable else ":ro"
        return (
            f"$D run --rm {interactive}--pull missing --label {HELPER_LABEL} --network none "
            f"-v {q(self.name)}:{_VOLUME_ROOT}{mode} {BUSYBOX_IMAGE} "
            f"sh -c {q(script)} sh {quoted_args}"
        )


def build_list_command(target: Target, path: str) -> str:
    return target.run(_LIST_SCRIPT, target.inside(path))


def parse_listing(raw: str) -> list[dict[str, object]] | None:
    """Entries of `build_list_command`'s output, directories first; None
    when the directory does not exist. Never raises."""
    if "@@DC_NODIR" in raw:
        return None
    entries: list[dict[str, object]] = []
    for line in raw.splitlines():
        parts = line.split("|", 6)
        if len(parts) != 7 or not parts[6] or "/" in parts[6]:
            continue
        kind_text = parts[0].lower()
        if "directory" in kind_text:
            kind = "dir"
        elif "symbolic link" in kind_text:
            kind = "link"
        elif "regular" in kind_text:
            kind = "file"
        else:
            kind = "other"
        entries.append(
            {
                "name": parts[6][:255],
                "kind": kind,
                "size": int(parts[1]) if parts[1].isdigit() else None,
                "mtime": int(parts[2]) if parts[2].isdigit() else None,
                "mode": parts[3][:10],
                "owner": f"{parts[4][:32]}:{parts[5][:32]}",
            }
        )
    entries.sort(key=lambda e: (e["kind"] != "dir", str(e["name"]).lower()))
    return entries


def build_read_command(target: Target, path: str, limit: int) -> str:
    """A tar stream of `path` (a file, or a directory with everything in
    it), cut at `limit` + 1 bytes so an oversized one is recognised."""
    inside = target.inside(path)
    if target.kind == "container":
        command = f"$D cp {q(target.name)}:{q(inside)} -"
    else:
        parent, base = posixpath.split(inside)
        # "./name": a name starting with "-" is never read as an option.
        command = target.run('tar -C "$1" -cf - "./$2"', parent or "/", base or ".")
    return f"{command} | head -c {int(limit) + 1}"


@dataclass(frozen=True)
class ReadFile:
    name: str
    content: bytes
    mode: int
    uid: int
    gid: int


def first_file(tar_bytes: bytes) -> ReadFile | None:
    """The first regular file in a tar stream, or None (a directory, a
    broken or empty stream)."""
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            for member in archive:
                if not member.isreg():
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    return None
                return ReadFile(
                    name=posixpath.basename(member.name),
                    content=handle.read(),
                    mode=member.mode,
                    uid=member.uid,
                    gid=member.gid,
                )
    except (tarfile.TarError, OSError, EOFError, ValueError):
        return None
    return None


def first_member_owner(tar_head: bytes) -> tuple[int, int, int] | None:
    """(mode, uid, gid) of the first regular file in the start of a tar
    stream — enough bytes for its header (`HEADER_BYTES`), not its data."""
    try:
        info = tarfile.TarInfo.frombuf(tar_head[:512], "utf-8", "surrogateescape")
    except (tarfile.TarError, ValueError):
        return None
    if not info.isreg():
        return None
    return info.mode, info.uid, info.gid


# Bytes of a tar stream that hold its first header.
HEADER_BYTES = 512


def build_tar(name: str, content: bytes, *, mode: int = 0o644, uid: int = 0, gid: int = 0) -> bytes:
    """A tar stream with one file, for `build_write_command`."""
    if not name or "/" in name or name in (".", "..") or "\0" in name:
        raise DockerCommandError("Invalid file name.")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        info.mode = mode & 0o7777
        info.uid, info.gid = uid, gid
        info.mtime = int(time.time())
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def build_write_command(target: Target, directory: str) -> str:
    """Unpack the tar stream on standard input into `directory`, keeping
    the owners and modes it carries."""
    inside = target.inside(directory)
    if target.kind == "container":
        return f"$D cp -a - {q(target.name)}:{q(inside)}"
    return target.run('tar -C "$1" -xpf -', inside, writable=True, stdin=True)


def build_delete_command(target: Target, path: str) -> str:
    inside = target.inside(path)
    if inside in ("/", _VOLUME_ROOT):
        raise DockerCommandError("The top directory can't be deleted.")
    return target.run('rm -rf -- "$1" && echo @@DC_DONE', inside, writable=True)


def build_mkdir_command(target: Target, path: str) -> str:
    inside = target.inside(path)
    return target.run('mkdir -p -- "$1" && echo @@DC_DONE', inside, writable=True)
