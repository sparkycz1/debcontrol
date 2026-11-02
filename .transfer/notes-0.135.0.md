## Changes

### App health: live fleet pages, a 3x lighter dashboard, layout fixes on small screens, dependencies (0.135.0) (#146)

### Live updates
- The Dashboard's machine cards, Docker -> Containers and the machines
  table on Docker -> Settings now refresh by themselves, like the machine
  list already did: the cards when a machine goes up or down or its
  updates change, the Docker pages when a Docker job (update, deploy,
  pull, restore, clean-up, ...) finishes on any machine. Ticked rows are
  kept, and a block is not swapped while you type in it or have its row
  menu open. Bursts are coalesced (at most one refresh every 5 s).
- A finished Docker job now also rings the fleet-wide live channel. As
  before, the message says only what kind of thing changed; every page
  re-fetches through its normal permission-checked route.

### Faster
- OS logos are drawn from one cached static sprite
  (`/static/img/os-badges.svg`) instead of a ~3 KB inline path for every
  machine. With 500 machines the Dashboard went from 2.2 MB to 0.7 MB and
  its cards render in 0.11 s instead of 0.43 s; the machine list shrinks
  the same way.
- The fleet cards template no longer emits blank lines between cards.

### Layout on small screens
Every page (134 page types) was checked for horizontal overflow at phone
(390 px), tablet (768 px) and desktop (1280 px) widths. Fixed:
- Settings: the SSH key fingerprint no longer widens the page on a phone.
- Scheduling (new / edit task): long option labels in selects no longer
  widen the page.
- Audit -> terminal recording: the player scrolls sideways when the
  recording is wider than the screen.
- Docker -> Containers on a tablet: a hidden accessibility label no
  longer adds a sideways scroll to the whole page.

### Dependencies
- Updated: amqp 5.4.2, authlib 1.9.2, billiard 4.3.2, cbor2 6.2.0.post2,
  openai 3.42.1, pytest-asyncio 1.4.1.post1, types-authlib; GitHub
  Actions: astral-sh/setup-uv 10.3.3.
- Already current: Docker images (python 3.15.2-slim, postgres 18.6,
  timescaledb 2.31.0-pg18, redis 8.10.3, caddy 2.11.7), vendored htmx
  2.0.11, xterm.js 6.0.0, Swagger UI 5.34.1, every other GitHub Action.
- Held back by another package (nothing to do until they release):
  redis-py stays on 6.4 (8.1 is out) because Celery's kombu requires
  `redis<6.5`; tenacity stays on 9.1.4 (9.2.1 is out) because google-genai
  pins it; pyee stays on 14 (16 is out) because Playwright pins it.
  PyYAML and atheris still have no Python 3.15 wheel.

### Clean-up and security
- Removed unused code: `job_label`, `open_connection_count`,
  `reset_cache`, `source_host`, and the two old flatpak/snap count parsers
  (the package-list parsers replace them).
- Tests can no longer open a real SSH connection by accident (it fails at
  once instead of waiting out a 10 s timeout); the test suite is faster.
- Security review: every mutating route has CSRF and a permission check
  (the route contract test covers them all), SQL built from strings uses
  code constants only, `| safe` in templates only on escaped or
  code-built markup, ruff's security rules are clean. No findings.

### Upgrade notes
No database migration, no configuration change.


**Full diff:** https://github.com/sparkycz1/debcontrol/compare/v0.134.0...v0.135.0
