"""Managed machines (`/machines`) — the router the app mounts.

The routes themselves live in one module per area, each with its own
`APIRouter`, included here in a fixed order:

- `machines_list` — the list, saved views, adding and importing machines,
  configuration export/import and the bulk actions (every fixed path).
- `machines_detail` — one machine: Overview, editing, onboarding, host key,
  facts/packages/services, History, notes, Proxmox, Docker, power, delete,
  acknowledging a problem.
- `machines_updates` — the Updates tab: check, preview, run, roll back,
  holds, changelog, run history.
- `machines_monitoring` — the Monitoring tab and its "Refresh now".
- `machines_logs` — the Logs tab, saved log views, the file browser, and
  the Terminal page.

`machines_common` holds what they share."""

from __future__ import annotations

from fastapi import APIRouter

from app.web.routes import (
    machines_detail,
    machines_list,
    machines_logs,
    machines_monitoring,
    machines_updates,
)

router = APIRouter()
# Order matters: a fixed path (`/new`, `/bulk/...`) has to be registered
# before a `/{id}/...` path that would otherwise swallow it.
router.include_router(machines_list.router)
router.include_router(machines_detail.router)
router.include_router(machines_updates.router)
router.include_router(machines_monitoring.router)
router.include_router(machines_logs.router)
