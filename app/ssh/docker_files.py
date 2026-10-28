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

import difflib
import hashlib
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
# What opens in the editor. Saving posts it back as a multipart form field,
# which Starlette caps at 1 MiB; with CRLF line endings from the browser a
# 256 KiB file stays well inside that.
MAX_EDIT_BYTES = 256 * 1024
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


# --- Several files at once, folders as archives, changes before saving ------------

# Files in one upload (a folder from the browser counts each file in it).
MAX_UPLOAD_FILES = 1000
# Lines of a "show changes" diff shown; the rest is summarized.
MAX_DIFF_LINES = 2000


def content_sha256(content: bytes) -> str:
    """The fingerprint of a file as opened in the editor: saving with it
    refuses to overwrite a file that changed on the machine meanwhile."""
    return hashlib.sha256(content).hexdigest()


def relative_upload_path(name: str) -> str:
    """A file's path inside the folder it is uploaded to, as the browser
    sends it ("notes.txt", or "photos/2026/a.jpg" for a folder upload).
    Every part must be a plain name: no "..", nothing absolute, no control
    characters. Raises `DockerCommandError`."""
    name = name.replace("\\", "/")
    parts = [part for part in name.split("/") if part]
    if not parts or len(parts) > 32 or len(name) > 4096:
        raise DockerCommandError("Invalid file name.")
    for part in parts:
        if part in (".", "..") or len(part) > 255 or any(ord(c) < 32 or c == "\x7f" for c in part):
            raise DockerCommandError("Invalid file name.")
    return "/".join(parts)


def build_upload_tar(files: list[tuple[str, bytes]]) -> bytes:
    """A tar stream of several files under relative paths
    (`relative_upload_path`), with the folders they need. New files are
    root's with mode 644, folders 755; an existing file of the same name is
    replaced."""
    if not files or len(files) > MAX_UPLOAD_FILES:
        raise DockerCommandError("Invalid upload.")
    now = int(time.time())
    seen_dirs: set[str] = set()
    seen_files: set[str] = set()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for raw_name, content in files:
            name = relative_upload_path(raw_name)
            if name in seen_files or name in seen_dirs:
                raise DockerCommandError("The same file is in the upload twice.")
            parts = name.split("/")
            for depth in range(1, len(parts)):
                folder = "/".join(parts[:depth])
                if folder in seen_files:
                    raise DockerCommandError("Invalid upload.")
                if folder not in seen_dirs:
                    seen_dirs.add(folder)
                    info = tarfile.TarInfo(name=f"./{folder}")
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.mtime = now
                    archive.addfile(info)
            seen_files.add(name)
            info = tarfile.TarInfo(name=f"./{name}")
            info.size = len(content)
            info.mode = 0o644
            info.mtime = now
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def check_upload_tar(tar_bytes: bytes) -> int:
    """Check, before it is unpacked on the machine, that a tar stream holds
    only regular files and folders under relative paths that stay where
    they are unpacked. Returns the number of files; raises
    `DockerCommandError`."""
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            for member in archive:
                if not (member.isreg() or member.isdir()):
                    raise DockerCommandError("Invalid upload.")
                name = member.name.removeprefix("./")
                if name.startswith("/") or relative_upload_path(name) != name.rstrip("/"):
                    raise DockerCommandError("Invalid upload.")
                if member.isreg():
                    count += 1
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise DockerCommandError("Invalid upload.") from exc
    if count == 0 or count > MAX_UPLOAD_FILES:
        raise DockerCommandError("Invalid upload.")
    return count


def is_tar_stream(tar_bytes: bytes) -> bool:
    """Whether `tar_bytes` is a complete tar stream (a folder read with
    `build_read_command`), not one cut short."""
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            for member in archive:
                if member.isreg() and archive.extractfile(member) is None:
                    return False
            return bool(archive.getmembers())
    except (tarfile.TarError, OSError, EOFError, ValueError):
        return False


def archive_filename(target: Target, path: str) -> str:
    """`<folder>.tar.gz` for a folder download (the container's or the
    volume's name for its top folder)."""
    base = posixpath.basename(normalize_path(path)) or target.name
    return f"{base}.tar.gz"


@dataclass(frozen=True)
class TextDiff:
    lines: list[str]
    added: int
    removed: int
    truncated: bool

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


def text_diff(old: str, new: str, path: str) -> TextDiff:
    """A unified diff of the file on the machine (`old`) and what is about
    to be saved (`new`), at most `MAX_DIFF_LINES` lines of it."""
    lines: list[str] = []
    added = removed = 0
    truncated = False
    for line in difflib.unified_diff(
        old.splitlines(),
        new.splitlines(),
        fromfile=f"{path} (on the machine)",
        tofile=f"{path} (edited)",
        lineterm="",
        n=3,
    ):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
        if len(lines) < MAX_DIFF_LINES:
            lines.append(line)
        else:
            truncated = True
    return TextDiff(lines, added, removed, truncated)
