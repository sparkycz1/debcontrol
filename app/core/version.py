"""Version metadata shown on the Settings page — a plain "which version is
this, exactly" answer after `scripts/upgrade.sh` (or any other deploy) pulls
a new release.

`APP_VERSION` is bumped by hand per release — there's no automated semantic
versioning yet, just a string here that should track the git tag. The git
commit itself is captured two different ways depending on how the app is
running:

- In the Docker image (built via `./scripts/upgrade.sh` or a plain
  `docker compose build`), it's baked in as the `GIT_COMMIT` build arg,
  which becomes an `ENV` in the image (see `Dockerfile`) — the `.git`
  directory itself is never copied in.
- Running locally without Docker (`uv run uvicorn ...`), `GIT_COMMIT` isn't
  set, so this falls back to asking the local git checkout directly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

APP_VERSION = "0.58.1"

# The canonical repo this version's commit hash links to, for the Settings
# page's "view this commit on GitHub" link. A fork should update this.
REPOSITORY_URL = "https://github.com/sparkycz1/debcontrol"

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@lru_cache
def get_git_commit() -> str | None:
    """Full commit hash the running code was built from, or None if it
    can't be determined (no `GIT_COMMIT` baked in, and no local `.git`
    either — e.g. a tarball download)."""
    env_value = os.environ.get("GIT_COMMIT", "").strip()
    if env_value and env_value.lower() != "unknown":
        return env_value

    git_path = shutil.which("git")
    if git_path is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603 - fixed args, no user input
            [git_path, "rev-parse", "HEAD"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def commit_url(commit: str) -> str:
    return f"{REPOSITORY_URL}/commit/{commit}"
