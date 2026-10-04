#!/usr/bin/env python3
"""Keep the files debcontrol and honeypot-shelf share word for word in step.

The two apps are meant to look and work the same; a handful of files
(the chart code and script, a few templates, the search and time-window
helpers) are identical in both and listed in `shared-ui.json` with a
SHA-256 each. `tests/test_shared_ui.py` fails when one of them no longer
matches its recorded hash, so a change to a shared file can't land in one
app unnoticed.

After changing a shared file on purpose:

    python scripts/sync_shared_ui.py --update          # here: record the new hashes
    python scripts/sync_shared_ui.py --to ../other-app # there: copy files + manifest

and commit both repositories.

    python scripts/sync_shared_ui.py --check                 # this tree against its manifest
    python scripts/sync_shared_ui.py --check-against <dir>   # this tree against another checkout
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "shared-ui.json"


def digest(path: Path) -> str:
    """SHA-256 of the file with line endings normalised (a Windows checkout
    must hash the same as a Linux one)."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def load(root: Path) -> dict[str, str]:
    files: dict[str, str] = json.loads((root / MANIFEST).read_text(encoding="utf-8"))["files"]
    return files


def write(root: Path, files: dict[str, str]) -> None:
    manifest = {
        "about": (
            "Files debcontrol and honeypot-shelf share word for word. "
            "See scripts/sync_shared_ui.py."
        ),
        "files": dict(sorted(files.items())),
    }
    (root / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def mismatches(root: Path, files: dict[str, str]) -> list[str]:
    problems = []
    for name, expected in files.items():
        path = root / name
        if not path.is_file():
            problems.append(f"{name}: missing")
        elif digest(path) != expected:
            problems.append(f"{name}: differs from {MANIFEST}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="this tree against its manifest")
    group.add_argument("--update", action="store_true", help="record this tree's hashes")
    group.add_argument("--to", metavar="DIR", help="copy the shared files and manifest there")
    group.add_argument(
        "--check-against", metavar="DIR", help="compare this tree with another checkout"
    )
    args = parser.parse_args()
    files = load(ROOT)

    if args.update:
        write(ROOT, {name: digest(ROOT / name) for name in files})
        print(f"{MANIFEST}: {len(files)} hashes recorded")
        return 0

    if args.check:
        problems = mismatches(ROOT, files)
    elif args.to:
        problems = mismatches(ROOT, files)
        if not problems:
            target = Path(args.to).resolve()
            for name in files:
                destination = target / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
            write(target, files)
            print(f"copied {len(files)} files and {MANIFEST} to {target}")
            return 0
    else:
        other = Path(args.check_against).resolve()
        problems = [
            f"{name}: not the same in {other}"
            for name in files
            if not (other / name).is_file() or digest(other / name) != digest(ROOT / name)
        ]
        if load(other) != files:
            problems.append(f"{MANIFEST}: not the same in {other}")

    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print(f"{len(files)} shared files match")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
