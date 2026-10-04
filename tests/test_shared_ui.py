"""The files this app shares word for word with its sister app
(debcontrol / honeypot-shelf) still match `shared-ui.json`.

A failure here means a shared file was edited in this repository only.
Make the same change in the other app — `scripts/sync_shared_ui.py` copies
the files across and records the new hashes — rather than letting the two
drift apart.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent


def _sync_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "sync_shared_ui", ROOT / "scripts" / "sync_shared_ui.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shared_files_match_the_manifest() -> None:
    sync = _sync_script()
    problems = sync.mismatches(ROOT, sync.load(ROOT))
    assert not problems, (
        "shared with the sister app — change it there too "
        f"(scripts/sync_shared_ui.py): {problems}"
    )


def test_the_manifest_lists_real_files_once() -> None:
    manifest = json.loads((ROOT / "shared-ui.json").read_text(encoding="utf-8"))
    files = manifest["files"]
    assert files, "shared-ui.json lists no files"
    assert list(files) == sorted(files), "keep shared-ui.json sorted"
    for name, sha in files.items():
        assert (ROOT / name).is_file(), name
        assert len(sha) == 64


def test_line_endings_do_not_change_the_hash(tmp_path: Path) -> None:
    sync = _sync_script()
    unix, windows = tmp_path / "a.txt", tmp_path / "b.txt"
    unix.write_bytes(b"one\ntwo\n")
    windows.write_bytes(b"one\r\ntwo\r\n")
    assert sync.digest(unix) == sync.digest(windows)
