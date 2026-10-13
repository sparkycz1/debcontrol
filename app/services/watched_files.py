"""Watching chosen files on a machine for changes.

A person lists a few paths per machine (`MachineWatchedFile`). Each facts
refresh reads them over SSH; the first reading is the baseline, and any
later difference is recorded on the machine's History, sent to the
"configuration changed" notification rules, and kept as a diff against
the version before.

**What is stored and who sees it.** The current and the previous content
of each file, encrypted like every other secret in this app — a
configuration file can hold a password. The diff is shown only with
`machine.manage`; a notification and the History say *which* file changed
and by how many lines, never what the lines are.

Only files the machine's account can read are watched (no `sudo` is used:
the sudoers rule debcontrol installs does not, and should not, cover
reading arbitrary files), and only up to `MAX_BYTES` each.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
import re
import shlex
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.machine import Machine
from app.db.models.machine_change import MachineChange
from app.db.models.machine_watched_file import MachineWatchedFile
from app.db.models.notification_rule import NotificationEventType
from app.services.notifications import notify

MAX_FILES = 20
MAX_BYTES = 65536
CHANGE_FIELD = "watched_file"

STATE_PENDING = "pending"
STATE_OK = "ok"
STATE_MISSING = "missing"
STATE_UNREADABLE = "unreadable"
STATE_TOO_LARGE = "too_large"
_STATES = (STATE_OK, STATE_MISSING, STATE_UNREADABLE, STATE_TOO_LARGE)

_PATH_RE = re.compile(r"^/[A-Za-z0-9_./@+-]{1,500}$")
_MARKER_RE = re.compile(r"^===FILE (\d{1,3}) (\w{1,16})===$")


class WatchedFilesError(ValueError):
    """What is wrong with a list of paths — text for the person who typed it."""


def parse_paths(text: str) -> list[str]:
    """Paths from the form: one per line, absolute, made of plain
    characters, no `..`; duplicates dropped, order kept."""
    paths: list[str] = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        path = raw.strip()
        if not path:
            continue
        if not _PATH_RE.match(path) or ".." in path.split("/") or path.endswith("/"):
            raise WatchedFilesError(
                f'"{path[:80]}" is not usable: give the full path of a file, made of letters, '
                "digits and _ . / @ + - only."
            )
        if path not in paths:
            paths.append(path)
    if len(paths) > MAX_FILES:
        raise WatchedFilesError(f"At most {MAX_FILES} files can be watched on one machine.")
    return paths


async def list_files(db: AsyncSession, machine_id: uuid.UUID) -> list[MachineWatchedFile]:
    result = await db.execute(
        select(MachineWatchedFile)
        .where(MachineWatchedFile.machine_id == machine_id)
        .order_by(MachineWatchedFile.path)
    )
    return list(result.scalars().all())


async def set_paths(db: AsyncSession, machine: Machine, paths: list[str]) -> tuple[int, int]:
    """Make `paths` the machine's watched files: new ones are added (to be
    read at the next check), dropped ones are deleted with what was stored
    of them. Commits. Returns (added, removed)."""
    existing = {row.path: row for row in await list_files(db, machine.id)}
    added = [path for path in paths if path not in existing]
    removed = [row for path, row in existing.items() if path not in paths]
    for row in removed:
        await db.delete(row)
    db.add_all(MachineWatchedFile(machine_id=machine.id, path=path) for path in added)
    await db.commit()
    return len(added), len(removed)


def build_command(paths: list[str]) -> str:
    """One round trip reading every file: a `===FILE <n> <state>===` line
    per path, followed for a readable one by its content in base64."""
    parts = []
    for index, path in enumerate(paths):
        if not _PATH_RE.match(path):
            raise ValueError("Unusable path.")
        quoted = shlex.quote(path)
        parts.append(
            f"if [ ! -f {quoted} ]; then echo '===FILE {index} missing==='; "
            f"elif [ ! -r {quoted} ]; then echo '===FILE {index} unreadable==='; "
            f'elif [ "$(wc -c < {quoted})" -gt {MAX_BYTES} ]; then '
            f"echo '===FILE {index} too_large==='; "
            f"else echo '===FILE {index} ok==='; base64 < {quoted} | tr -d '\\n'; echo; fi"
        )
    return "; ".join(parts) if parts else "true"


def parse_output(raw: str, count: int) -> dict[int, tuple[str, str | None]]:
    """`{index: (state, content or None)}` for the files that reported.
    Content that is not text (or not valid base64) counts as unreadable."""
    found: dict[int, tuple[str, str | None]] = {}
    lines = raw.splitlines()
    for position, line in enumerate(lines):
        marker = _MARKER_RE.match(line.strip())
        if marker is None:
            continue
        index, state = int(marker.group(1)), marker.group(2)
        if index >= count or state not in _STATES:
            continue
        if state != STATE_OK:
            found[index] = (state, None)
            continue
        encoded = lines[position + 1].strip() if position + 1 < len(lines) else ""
        if _MARKER_RE.match(encoded):
            encoded = ""
        try:
            content = base64.b64decode(encoded, validate=True).decode("utf-8")
        except binascii.Error, UnicodeDecodeError, ValueError:
            found[index] = (STATE_UNREADABLE, None)
            continue
        found[index] = (STATE_OK, content.replace("\x00", ""))
    return found


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def line_counts(before: str, after: str) -> tuple[int, int]:
    """(lines added, lines removed) between two versions."""
    added = removed = 0
    for line in difflib.ndiff(before.splitlines(), after.splitlines()):
        if line.startswith("+ "):
            added += 1
        elif line.startswith("- "):
            removed += 1
    return added, removed


@dataclass(frozen=True)
class Change:
    path: str
    summary: str


def apply_reading(
    row: MachineWatchedFile, state: str, content: str | None, now: datetime
) -> Change | None:
    """Update `row` from one reading. Returns the change worth telling
    someone about, or None (the first reading, or nothing different)."""
    was_state, was_digest = row.state, row.sha256
    row.checked_at = now
    row.state = state
    if state != STATE_OK or content is None:
        if was_state == STATE_OK:
            row.changed_at = now
            return Change(row.path, {"missing": "the file is gone"}.get(state, state))
        return None
    digest = _digest(content)
    if was_digest == digest:
        return None
    previous = decrypt_secret(row.content_encrypted) if row.content_encrypted else None
    row.sha256 = digest
    row.content_encrypted = encrypt_secret(content)
    if previous is None:
        # The baseline: nothing to compare with yet.
        return None
    row.previous_content_encrypted = encrypt_secret(previous)
    row.lines_added, row.lines_removed = line_counts(previous, content)
    row.changed_at = now
    return Change(row.path, f"+{row.lines_added} / -{row.lines_removed} lines")


async def record_changes(db: AsyncSession, machine: Machine, changes: list[Change]) -> None:
    """History rows and one notification for `changes`; commits."""
    now = datetime.now(UTC)
    db.add_all(
        MachineChange(
            machine_id=machine.id,
            detected_at=now,
            category="file",
            field=CHANGE_FIELD,
            old_value=change.path,
            new_value=change.summary,
        )
        for change in changes
    )
    await db.commit()
    if not changes:
        return
    summary = "\n".join(f"File {change.path}: {change.summary}" for change in changes)
    await notify(
        db,
        NotificationEventType.MACHINE_CONFIG_CHANGED,
        machine=machine,
        context={"changes": summary, "details": summary},
    )


def diff_of(row: MachineWatchedFile) -> list[str]:
    """The last change of `row` as unified-diff lines; empty when there
    has not been one."""
    if not row.content_encrypted or not row.previous_content_encrypted:
        return []
    before = decrypt_secret(row.previous_content_encrypted).splitlines()
    after = decrypt_secret(row.content_encrypted).splitlines()
    return list(difflib.unified_diff(before, after, "before", "now", lineterm="", n=3))


def as_dict(row: MachineWatchedFile) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "path": row.path,
        "state": row.state,
        "sha256": row.sha256,
        "checked_at": row.checked_at.isoformat() if row.checked_at else None,
        "changed_at": row.changed_at.isoformat() if row.changed_at else None,
        "lines_added": row.lines_added,
        "lines_removed": row.lines_removed,
    }
