"""Recording browser terminal sessions and reading the recordings back —
see `app.db.models.terminal_recording` for what is kept and why.

`Recorder` collects one session's output as it is relayed
(`app/web/routes/terminal_ws.py`); `save` stores it when the session ends.
A recording is an asciicast v2 text (one JSON header line, then one
`[seconds, "o", text]` or `[seconds, "r", "COLSxROWS"]` line per event),
zlib-compressed and encrypted with the instance's key.
"""

from __future__ import annotations

import base64
import codecs
import json
import time
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.machine import Machine
from app.db.models.terminal_recording import TerminalRecording
from app.db.models.user import User

# One recording holds at most this much terminal output; a session that
# prints more (a long build, `cat` of a big file) is recorded up to here
# and marked truncated. Keeps one row, and one replay, a sane size.
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
# How many recordings the list page shows per page.
PAGE_SIZE = 50


@dataclass
class Recorder:
    """One session's output, timed from the moment the shell opened."""

    cols: int
    rows: int
    started: float = field(default_factory=time.monotonic)
    events: list[tuple[float, str, str]] = field(default_factory=list)
    output_bytes: int = 0
    truncated: bool = False
    _decoder: Any = field(
        default_factory=lambda: codecs.getincrementaldecoder("utf-8")("replace"), repr=False
    )

    def _elapsed(self) -> float:
        return round(time.monotonic() - self.started, 3)

    def output(self, chunk: bytes) -> None:
        """Called with every chunk relayed to the browser."""
        if self.truncated or not chunk:
            return
        room = MAX_OUTPUT_BYTES - self.output_bytes
        if len(chunk) > room:
            chunk = chunk[:room]
            self.truncated = True
        self.output_bytes += len(chunk)
        # Incremental: a multi-byte character split across two chunks is
        # decoded once both halves are in.
        text = self._decoder.decode(chunk)
        if text:
            self.events.append((self._elapsed(), "o", text))

    def resize(self, cols: int, rows: int) -> None:
        self.events.append((self._elapsed(), "r", f"{cols}x{rows}"))

    def cast(self) -> str:
        header = {"version": 2, "width": self.cols, "height": self.rows}
        lines = [json.dumps(header)]
        lines.extend(json.dumps(list(event), ensure_ascii=False) for event in self.events)
        return "\n".join(lines) + "\n"


def pack(cast: str) -> bytes:
    """Compress and encrypt an asciicast for `data_encrypted`."""
    compressed = zlib.compress(cast.encode("utf-8"), level=6)
    return encrypt_secret(base64.b64encode(compressed).decode("ascii"))


def unpack(data: bytes) -> str:
    return zlib.decompress(base64.b64decode(decrypt_secret(data))).decode("utf-8")


def parse_cast(cast: str) -> dict[str, Any]:
    """`{"cols", "rows", "events": [[seconds, kind, data], ...]}` for the
    player and the API. Lines that are not a well-formed event are skipped."""
    lines = cast.splitlines()
    header: dict[str, Any] = {}
    if lines:
        try:
            parsed = json.loads(lines[0])
        except ValueError:
            parsed = {}
        header = parsed if isinstance(parsed, dict) else {}
    events: list[list[Any]] = []
    for line in lines[1:]:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if (
            isinstance(event, list)
            and len(event) == 3
            and isinstance(event[0], int | float)
            and event[1] in ("o", "r")
            and isinstance(event[2], str)
        ):
            events.append(event)
    return {
        "cols": int(header.get("width") or 80),
        "rows": int(header.get("height") or 24),
        "events": events,
    }


async def save(
    db: AsyncSession,
    recorder: Recorder,
    *,
    machine: Machine,
    user: User,
    started_at: datetime,
    duration_seconds: float,
) -> TerminalRecording | None:
    """Store the session's recording; None when it showed nothing."""
    if not recorder.events:
        return None
    recording = TerminalRecording(
        machine_id=machine.id,
        machine_name=machine.name,
        username=user.username,
        started_at=started_at,
        duration_seconds=round(duration_seconds, 1),
        cols=recorder.cols,
        rows=recorder.rows,
        output_bytes=recorder.output_bytes,
        truncated=recorder.truncated,
        data_encrypted=pack(recorder.cast()),
    )
    db.add(recording)
    await db.commit()
    return recording


async def list_recordings(
    db: AsyncSession, *, machine_id: uuid.UUID | None = None, page: int = 1
) -> tuple[list[TerminalRecording], bool]:
    """One page, newest first, without the recordings' data; and whether
    an older page exists."""
    query = (
        select(TerminalRecording)
        .options(defer(TerminalRecording.data_encrypted))
        .order_by(TerminalRecording.started_at.desc())
    )
    if machine_id is not None:
        query = query.where(TerminalRecording.machine_id == machine_id)
    offset = (max(page, 1) - 1) * PAGE_SIZE
    result = await db.execute(query.offset(offset).limit(PAGE_SIZE + 1))
    rows = list(result.scalars().all())
    return rows[:PAGE_SIZE], len(rows) > PAGE_SIZE


def as_dict(recording: TerminalRecording) -> dict[str, Any]:
    return {
        "id": str(recording.id),
        "machine_id": str(recording.machine_id) if recording.machine_id else None,
        "machine_name": recording.machine_name,
        "username": recording.username,
        "started_at": recording.started_at.isoformat(),
        "duration_seconds": recording.duration_seconds,
        "cols": recording.cols,
        "rows": recording.rows,
        "output_bytes": recording.output_bytes,
        "truncated": recording.truncated,
    }
