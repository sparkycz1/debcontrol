"""Scheduling: run an existing action (system update, update check, reboot,
shut down, ...) against a machine, a group, or "All machines" on a cron-like
schedule.

See:
- `app.scheduling.actions` — the registry a schedulable action plugs into.
- `app.scheduling.builtin_actions` — what's actually registered today;
  `register_builtin_actions()` must run once before the registry is used
  (both `app.main` and `app.tasks.worker` call it at import time).
- `app.scheduling.cron` — cron expression validation / next-run computation.
- `app.scheduling.jobs` — the arq jobs that evaluate and fire due schedules.
"""

from __future__ import annotations
