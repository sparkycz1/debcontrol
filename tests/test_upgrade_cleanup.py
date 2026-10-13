"""What `scripts/upgrade.sh` removes afterwards (`scripts/upgrade_cleanup.sh`):
only what debcontrol itself used, including what an earlier upgrade left
behind — run here against a stand-in for `docker`."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parent.parent / "scripts" / "upgrade_cleanup.sh"

# `docker` as a shell function: images that exist are the lines of
# ./present, the ones in ./busy cannot be removed, every removal is logged.
_FAKE_DOCKER = r"""
docker() {
  case "$1 $2" in
    "image inspect")
      if [ "$3" = "-f" ]; then echo "sha256:new"; return 0; fi
      grep -qxF "$3" present ;;
    "image rm")
      if grep -qxF "$3" busy 2>/dev/null; then return 1; fi
      grep -vxF "$3" present > present.tmp; mv present.tmp present; echo "rm $3" >> calls ;;
    "image prune") echo "deleted: sha256:old1" ;;
    "ps -aq") echo "c0ffee" ;;
    "rm c0ffee") echo "rm-container" >> calls ;;
    "builder prune") echo "Total reclaimed space: 1.2GB" ;;
  esac
}
"""

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None,
    reason="runs the script's own bash",
)


def _run(tmp_path: Path, body: str) -> str:
    script = f'{_FAKE_DOCKER}\n. "{_SCRIPT}"\n: > calls\n{body}\n'
    result = subprocess.run(  # noqa: S603 - our own script, fixed arguments
        ["bash", "-c", script],  # noqa: S607
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.stderr == ""
    return result.stdout


def test_only_images_this_stack_used_are_removed(tmp_path: Path) -> None:
    (tmp_path / "present").write_text(
        "postgres:18.5\nredis:8.10.1\nredis:8.10.2\npostgres:18.6\nother/app:1\n"
    )
    # Left behind by an earlier upgrade, and one something else still uses.
    (tmp_path / "state").write_text("redis:8.10.1\n")
    (tmp_path / "busy").write_text("postgres:18.5\n")
    before = "debcontrol:local\\npostgres:18.5\\nredis:8.10.2"
    now = "debcontrol:local\\npostgres:18.6\\nredis:8.10.2"

    first = _run(tmp_path, f'cleanup_images state "$(printf "{before}")" "$(printf "{now}")"')
    remembered = (tmp_path / "state").read_text().split()
    (tmp_path / "busy").write_text("")
    second = _run(tmp_path, f'cleanup_images state "$(printf "{now}")" "$(printf "{now}")"')

    assert "removed redis:8.10.1" in first and "kept postgres:18.5 (still in use)" in first
    # What could not go yet is remembered for next time.
    assert remembered == ["debcontrol:local", "postgres:18.5", "postgres:18.6", "redis:8.10.2"]
    assert "removed postgres:18.5" in second
    assert (tmp_path / "state").read_text().split() == [
        "debcontrol:local",
        "postgres:18.6",
        "redis:8.10.2",
    ]
    assert "other/app:1" in (tmp_path / "present").read_text()


def test_old_builds_one_off_containers_and_build_cache(tmp_path: Path) -> None:
    (tmp_path / "present").write_text("debcontrol:local\n")

    output = _run(tmp_path, 'cleanup_app_builds "sha256:old"; cleanup_leftovers')

    assert "removed the previous debcontrol image" in output
    assert "removed older debcontrol builds" in output
    assert "removed a finished one-off container" in output
    assert "build cache: freed 1.2GB" in output


def test_the_script_never_touches_volumes_or_prunes_the_whole_host() -> None:
    text = _SCRIPT.read_text(encoding="utf-8") + (_SCRIPT.parent / "upgrade.sh").read_text(
        encoding="utf-8"
    )
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))

    assert "system prune" not in code
    assert "volume" not in code
