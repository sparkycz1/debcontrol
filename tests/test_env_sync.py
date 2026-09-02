"""`scripts/env_sync.py` — adding whatever `.env.example` variables are
missing from an existing `.env`, used by `scripts/setup.py` (keeping an
existing `.env`) and `scripts/upgrade.sh` (after `git pull`).
"""

from __future__ import annotations

from pathlib import Path

from scripts.env_sync import compute_missing_blocks, sync_env

_EXAMPLE = """\
# Preamble comment, not attached to any key.

# --- Section ---
APP_ENV=development
# A knob with a real default.
FACTS_REFRESH_INTERVAL_SECONDS=3600
# Optional, commented out by default.
# REACHABILITY_CHECK_CONCURRENCY=20
"""


def test_compute_missing_blocks_empty_env_wants_everything():
    missing = compute_missing_blocks("", _EXAMPLE)

    assert [key for key, _lines in missing] == [
        "APP_ENV",
        "FACTS_REFRESH_INTERVAL_SECONDS",
        "REACHABILITY_CHECK_CONCURRENCY",
    ]


def test_compute_missing_blocks_skips_keys_already_present():
    env_text = "APP_ENV=production\n"

    missing = compute_missing_blocks(env_text, _EXAMPLE)

    assert [key for key, _lines in missing] == [
        "FACTS_REFRESH_INTERVAL_SECONDS",
        "REACHABILITY_CHECK_CONCURRENCY",
    ]


def test_compute_missing_blocks_a_commented_key_still_counts_as_present():
    # A user who deliberately left something commented out must not have
    # it silently re-added/activated.
    env_text = "# REACHABILITY_CHECK_CONCURRENCY=50\n"

    missing = compute_missing_blocks(env_text, _EXAMPLE)

    assert "REACHABILITY_CHECK_CONCURRENCY" not in [key for key, _lines in missing]


def test_compute_missing_blocks_nothing_missing():
    env_text = "APP_ENV=x\nFACTS_REFRESH_INTERVAL_SECONDS=1\n# REACHABILITY_CHECK_CONCURRENCY=1\n"

    assert compute_missing_blocks(env_text, _EXAMPLE) == []


def test_compute_missing_blocks_preserves_commented_state():
    missing = compute_missing_blocks("", _EXAMPLE)
    by_key = dict(missing)

    assert by_key["FACTS_REFRESH_INTERVAL_SECONDS"][-1] == "FACTS_REFRESH_INTERVAL_SECONDS=3600"
    assert by_key["REACHABILITY_CHECK_CONCURRENCY"][-1] == "# REACHABILITY_CHECK_CONCURRENCY=20"


def test_sync_env_appends_missing_and_leaves_existing_untouched(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    example_path = tmp_path / ".env.example"
    env_path.write_text("APP_ENV=production\n", encoding="utf-8")
    example_path.write_text(_EXAMPLE, encoding="utf-8")

    added = sync_env(env_path, example_path)

    assert added == ["FACTS_REFRESH_INTERVAL_SECONDS", "REACHABILITY_CHECK_CONCURRENCY"]
    new_text = env_path.read_text(encoding="utf-8")
    assert "APP_ENV=production" in new_text  # untouched, not overwritten with the example's value
    assert "FACTS_REFRESH_INTERVAL_SECONDS=3600" in new_text
    assert "# REACHABILITY_CHECK_CONCURRENCY=20" in new_text


def test_sync_env_no_op_when_nothing_missing(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    example_path = tmp_path / ".env.example"
    env_path.write_text(
        "APP_ENV=x\nFACTS_REFRESH_INTERVAL_SECONDS=1\n# REACHABILITY_CHECK_CONCURRENCY=1\n",
        encoding="utf-8",
    )
    example_path.write_text(_EXAMPLE, encoding="utf-8")
    before = env_path.read_text(encoding="utf-8")

    added = sync_env(env_path, example_path)

    assert added == []
    assert env_path.read_text(encoding="utf-8") == before


def test_sync_env_against_the_repos_real_env_example_is_idempotent(tmp_path: Path) -> None:
    """A real `.env.example` already containing every key it defines
    should sync cleanly against itself — the actual regression this
    script exists to prevent is a genuine, real-world example file
    tripping up the block-splitting logic."""
    from scripts.env_sync import REPO_ROOT

    example_path = REPO_ROOT / ".env.example"
    env_path = tmp_path / ".env"
    env_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")

    added = sync_env(env_path, example_path)

    assert added == []
