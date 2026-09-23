"""Turns raw log text (journal, file, `docker logs`) into what the Logs
tab renders: one entry per line with a severity guess for coloring, split
into plain/matched segments so the search term can be highlighted — all
plain strings, autoescaped by the template like any other value (log
content comes from the managed machine and is never trusted as markup)."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Word-ish matches only, so "terror" or "warnings_disabled=0" in a path
# doesn't paint a line red/yellow. Checked most-severe first.
_LEVELS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "error",
        re.compile(
            r"\b(error|err|fail(ed|ure)?|fatal|crit(ical)?|panic|emerg|alert|"
            r"exception|traceback|denied|segfault)\b",
            re.IGNORECASE,
        ),
    ),
    ("warn", re.compile(r"\b(warn(ing)?|deprecated)\b", re.IGNORECASE)),
    ("debug", re.compile(r"\b(debug|trace)\b", re.IGNORECASE)),
)


@dataclass(frozen=True)
class LogLine:
    level: str | None
    # (text, is_search_match) pairs, in order.
    segments: list[tuple[str, bool]]


def _level_of(line: str) -> str | None:
    for level, pattern in _LEVELS:
        if pattern.search(line):
            return level
    return None


def _segments(line: str, search: str) -> list[tuple[str, bool]]:
    """Split on exact (case-sensitive) occurrences of `search` — the same
    matching the machine-side `grep -F`/`journalctl -g` filter used, so
    what's highlighted is what matched."""
    if not search:
        return [(line, False)]
    parts: list[tuple[str, bool]] = []
    start = 0
    while (index := line.find(search, start)) != -1:
        if index > start:
            parts.append((line[start:index], False))
        parts.append((search, True))
        start = index + len(search)
    if start < len(line):
        parts.append((line[start:], False))
    return parts or [(line, False)]


def parse_log_lines(output: str | None, search: str = "") -> list[LogLine]:
    if not output:
        return []
    term = search.strip()
    return [
        LogLine(level=_level_of(line), segments=_segments(line, term))
        for line in output.splitlines()
    ]
