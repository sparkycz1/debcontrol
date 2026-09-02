#!/usr/bin/env python3
"""Adds whatever `.env.example` variables are missing from an existing
`.env` — run automatically by `scripts/setup.py` (when an existing `.env`
is kept rather than overwritten) and by `scripts/upgrade.sh` (after
`git pull`, since a new release can add new `.env.example` variables that
an existing `.env` predates).

Never touches a key already present in `.env`, in either commented or
uncommented form — this only ever *adds*, never overwrites a value someone
already configured (or deliberately left commented out). A key that's new
in `.env.example` is appended to `.env` exactly as `.env.example` has it
(commented if `.env.example` has it commented — a purely optional knob,
documented but inert until uncommented; uncommented with its example value
otherwise), together with whatever comment lines directly precede it in
`.env.example`, so it arrives in `.env` with the same explanation a fresh
install would see.

Usage:
    python scripts/env_sync.py [--env PATH] [--example PATH]

Prints one line per key added, or "Nothing to add — .env already has
every .env.example variable." Exit code is always 0 (nothing here is
worth failing an upgrade over) except for genuinely missing input files.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_KEY_LINE_RE = re.compile(r"^(#\s*)?([A-Za-z_][A-Za-z0-9_]*)=")


def _existing_keys(env_text: str) -> set[str]:
    """Every key `.env` already mentions, commented or not — a commented
    `# FOO=bar` still counts as "already has an opinion about FOO", so
    this never re-adds something a user deliberately left disabled."""
    keys = set()
    for line in env_text.splitlines():
        match = _KEY_LINE_RE.match(line)
        if match:
            keys.add(match.group(2))
    return keys


def _blocks(example_text: str) -> list[tuple[str, list[str]]]:
    """Splits `.env.example` into `(key, lines)` blocks — `lines` is the
    run of comment/blank lines immediately preceding a `KEY=`/`# KEY=`
    line, plus that line itself. A block with an empty key (`""`) is the
    leading preamble before the first real variable, always skipped by
    the caller."""
    blocks: list[tuple[str, list[str]]] = []
    pending: list[str] = []
    for line in example_text.splitlines():
        match = _KEY_LINE_RE.match(line)
        if match:
            pending.append(line)
            blocks.append((match.group(2), pending))
            pending = []
        else:
            pending.append(line)
    return blocks


def compute_missing_blocks(env_text: str, example_text: str) -> list[tuple[str, list[str]]]:
    """Pure function, no I/O — the `(key, lines)` blocks from
    `.env.example` whose key `env_text` doesn't mention at all yet, in
    `.env.example`'s own order."""
    existing = _existing_keys(env_text)
    seen: set[str] = set()
    missing: list[tuple[str, list[str]]] = []
    for key, lines in _blocks(example_text):
        if not key or key in existing or key in seen:
            continue
        seen.add(key)
        missing.append((key, lines))
    return missing


def sync_env(env_path: Path, example_path: Path) -> list[str]:
    """Appends whatever's missing to `env_path` in place. Returns the list
    of keys added (empty if there was nothing to do). Creates no backup —
    this only ever appends, never rewrites an existing line, so there's
    nothing destructive to undo."""
    env_text = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    example_text = example_path.read_text(encoding="utf-8")

    missing = compute_missing_blocks(env_text, example_text)
    if not missing:
        return []

    addition = "\n# --- Added by scripts/env_sync.py: new in a later release's .env.example ---\n"
    for _key, lines in missing:
        addition += "\n".join(lines) + "\n"

    with env_path.open("a", encoding="utf-8") as f:
        if env_text and not env_text.endswith("\n"):
            f.write("\n")
        f.write(addition)

    return [key for key, _lines in missing]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=REPO_ROOT / ".env")
    parser.add_argument("--example", type=Path, default=REPO_ROOT / ".env.example")
    args = parser.parse_args()

    if not args.example.exists():
        print(f"error: {args.example} not found.")
        raise SystemExit(1)
    if not args.env.exists():
        # Nothing to sync into — scripts/setup.py handles a from-scratch
        # .env itself; this is a no-op, not an error, so upgrade.sh can
        # call this unconditionally without checking first.
        print(f"No {args.env} yet — nothing to sync.")
        return

    added = sync_env(args.env, args.example)
    if not added:
        print("Nothing to add — .env already has every .env.example variable.")
        return

    print(f"Added {len(added)} new variable(s) to {args.env}: {', '.join(added)}")
    print("Review them (and set any that need a real value) before relying on this deploy.")


if __name__ == "__main__":
    main()
