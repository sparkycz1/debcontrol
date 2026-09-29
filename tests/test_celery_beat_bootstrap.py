"""`app.tasks.celery_app._bootstrap_interval_settings` — the one place the
Beat-schedule intervals are still read "once, at process start" (see that
function's own docstring), now from `AppSettings` instead of the
environment. Importing this module (which the whole test suite already
does, transitively, via `app.tasks.jobs`) must never touch a real
database — see CLAUDE.md's "no real Postgres/Redis/Celery broker" test
contract.
"""

from __future__ import annotations

import subprocess
import sys

from app.tasks.celery_app import _INTERVAL_SETTING_DEFAULTS, _bootstrap_interval_settings


def test_bootstrap_skips_the_database_outside_the_beat_process(monkeypatch):
    """Every process that imports this module (the web app, a worker, the
    test suite collecting `app.main`) except `celery ... beat` itself must
    get the built-in defaults immediately, with zero I/O — see the
    function's own docstring for why."""
    monkeypatch.setattr(sys, "argv", ["celery", "-A", "app.tasks.celery_app", "worker"])
    assert _bootstrap_interval_settings() == _INTERVAL_SETTING_DEFAULTS


def test_bootstrap_falls_back_to_defaults_when_the_database_is_unreachable(monkeypatch):
    """Simulates the one real code path a `beat` process can take at
    startup before Postgres is reachable/migrated — must degrade to the
    built-in defaults, never raise (a fresh instance's `beat` container
    should still start)."""
    monkeypatch.setattr(sys, "argv", ["celery", "-A", "app.tasks.celery_app", "beat"])

    def _boom(*args, **kwargs):
        raise ConnectionRefusedError("no database here")

    monkeypatch.setattr(
        "sqlalchemy.ext.asyncio.create_async_engine", _boom
    )
    assert _bootstrap_interval_settings() == _INTERVAL_SETTING_DEFAULTS


def test_importing_celery_app_alone_configures_every_mapper_cleanly():
    """Regression test for a real bug class (see honeypot-shelf's own
    `5a61e16`, ported here as a preventive fix rather than a live bug):
    SQLAlchemy configures every mapped class's relationships the first
    time *any one* of them is queried, and a relationship using a
    string/forward-reference annotation needs its target class already
    registered in the shared declarative registry at that exact moment.
    `app.tasks.celery_app` is the very first module a `beat` process
    imports, and `_bootstrap_interval_settings` (called at that module's
    own import time) queries `AppSettings` before `app.tasks.jobs` has had
    a chance to import every other model as a side effect.

    A genuinely fresh subprocess is required here — the normal test
    process has almost certainly already imported `app.tasks.jobs` (and
    therefore every model) from an earlier test, which would mask this
    bug entirely by coincidence of import order, not fix it."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import app.tasks.celery_app; "
                "from sqlalchemy.orm import configure_mappers; "
                "configure_mappers(); "
                "print('ok')"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


async def test_defaults_match_app_settings_column_defaults(db_session_factory):
    """The fallback values must track `AppSettings`'s own column defaults
    (app/db/models/app_settings.py) — otherwise a fresh, not-yet-migrated
    `beat` boot would schedule sweeps at a different cadence than what the
    Settings page shows once the database *is* reachable."""
    from app.db.models.app_settings import AppSettings

    async with db_session_factory() as db:
        row = AppSettings()
        db.add(row)
        await db.commit()
        await db.refresh(row)
        for key, value in _INTERVAL_SETTING_DEFAULTS.items():
            assert getattr(row, key) == value
