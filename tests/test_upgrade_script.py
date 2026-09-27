"""`scripts/upgrade.sh` is still being read by bash while its own `git pull`
replaces it on disk: after the pull, the old process carries on reading the
*new* file from the byte offset where the old one's pull block ended. So
everything up to and including that block must never change between
releases — new steps go below it. If this test fails, move your change
below the `git pull` block instead of updating the hash."""

from __future__ import annotations

import hashlib
from pathlib import Path

_PULL_BLOCK_END = b'  git pull --ff-only origin "$branch"\nfi\n'
_PREFIX_SHA256 = "d84f45dfc0fe0745d145d14f8e94b4dd438781c97f22488526cfeab1abbc6478"


def test_upgrade_script_prefix_is_unchanged():
    script = (Path(__file__).parent.parent / "scripts" / "upgrade.sh").read_bytes()
    end = script.index(_PULL_BLOCK_END) + len(_PULL_BLOCK_END)
    assert hashlib.sha256(script[:end]).hexdigest() == _PREFIX_SHA256
