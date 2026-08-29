# Architecture

## Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.14.7 | |
| Web framework | FastAPI | async, OpenAPI schema for free |
| Templates / UI | Jinja2 + [htmx](https://htmx.org) (vendored locally) | no SPA build, no CDN |
| Database | PostgreSQL 18.6 | via `asyncpg` + SQLAlchemy 2.0 (async); image pinned to an exact patch |
| Migrations | Alembic | async engine |
| Cache / task queue | Redis 8.8.2 | queue via [`arq`](https://github.com/python-arq/arq); image pinned to an exact patch |
| SSH client | [AsyncSSH](https://asyncssh.readthedocs.io/) | async, strict host key verification |
| Reverse proxy (optional) | [Caddy](https://caddyproxy.com/) | automatic HTTPS, TLS 1.3 only, HTTP/3 |
| Packaging / lockfile | [`uv`](https://docs.astral.sh/uv/) | `uv.lock` is committed |
| Containers | Docker (multi-stage build) + Docker Compose | |

### Why server-rendered + htmx, not a SPA

The app is an internal admin tool, not a public product with rich
client-side interactivity requirements. Server-rendered Jinja2 templates
mean: no separate frontend build/deploy pipeline, no client-side API
tokens to protect, and a much smaller attack surface (no JS framework
supply chain, no bundler). htmx is used sparingly for the two truly
async-feeling interactions (discovering a host key fingerprint, testing a
connection) and is vendored locally rather than pulled from a CDN.

### Why arq over Celery

`arq` is a thin, async-native task queue on top of Redis — it fits
naturally into an already-async FastAPI app without pulling in Celery's
much larger dependency and configuration surface. The trade-off: `arq` is
currently in "maintenance only" mode upstream, and it pins `redis-py <6`
(see [Installation](Installation.md) / the root `README.md` for the
version-pinning implications). If heavier queue features are needed later
(scheduling UI, retries with complex backoff, multiple queues/priorities),
Celery or `ReArq` are the natural next steps.

### Why AsyncSSH over Paramiko

AsyncSSH is fully asynchronous and integrates directly with FastAPI's
event loop, avoiding a thread pool just to do SSH I/O. It's actively
maintained and supports modern algorithms (Ed25519, etc.).

## Project structure

```
app/
  core/       config (pydantic-settings), logging, encryption, CSRF
  db/         SQLAlchemy models + async session
  schemas/    Pydantic schemas for forms
  ssh/        AsyncSSH client (host key pinning)
  tasks/      arq worker + background jobs
  web/        FastAPI routers, Jinja2 templates, static files
alembic/      DB migrations
tests/        pytest (async, isolated from real infrastructure)
scripts/      helper scripts (secret generation)
wiki/         this documentation
```

## Security model

The app has no user authentication yet. Everything below is scoped to
what's true *before* that lands — see the root `README.md`'s "What's
deliberately empty" section for what's coming later.

### SSH host key pinning

Covered in depth in
[SSH Host Key Verification](SSH-Host-Key-Verification.md). Summary: no
connection is ever made to a machine whose host key fingerprint hasn't
been explicitly confirmed by a human, and any later mismatch hard-fails
the connection instead of silently reconnecting.

### Secrets at rest

Machine passwords and the app's own SSH private key are encrypted in
Postgres using Fernet (AES + HMAC, from the `cryptography` package). The
encryption key lives only in the `ENCRYPTION_KEY` environment variable —
never in the database or the repo. This does **not** replace user
authentication; it protects SSH credentials from a database-only
compromise (a leaked backup, a misconfigured read replica, etc.).

### One shared SSH identity, not one key per machine

Rather than asking an operator to generate and paste a private key per
machine, debcontrol generates a single ed25519 keypair for itself on first
use (`app/ssh/identity.py`, `app/db/models/ssh_identity.py`) and reuses it
everywhere "SSH key" is the chosen auth method. The private half never
touches disk in plaintext — it's decrypted in memory only for the
duration of a connection. The public half is shown on the **Settings**
page; appending it to a machine's `~/.ssh/authorized_keys` is a manual
step today (see
[Managed Machine Requirements](Managed-Machine-Requirements.md)).
Per-machine passwords remain available as a fallback, with the UI calling
that out as not recommended.

### Self-registration is not the same as trust

`POST /api/inform` lets a machine announce itself (IP, hostname, basic
facts it can read locally) using a shared bearer token
(`INFORM_TOKEN`) — meant for a first-boot/cloud-init script, see
[Managed Machine Requirements](Managed-Machine-Requirements.md). This only
ever creates a `PendingMachine` row for a human to look at; it grants no
access and establishes no trust. Turning a pending entry into a real,
manageable `Machine` still goes through the ordinary add-machine form and
the mandatory host-key discovery/confirmation flow — self-registration
just pre-fills the IP/name so there's less retyping.

### System updates: the first bulk SSH operation

Running `apt-get update` / `dist-upgrade` or `full-upgrade` / `autoremove` /
`autoclean` (**Machines → a machine → System updates**, or the same action
scoped to a group / "All machines") is the first feature that (a) needs
root on the target and (b) can legitimately run for a long time. Both
shaped the design:

- **A dedicated long timeout.** `open_connection`'s timeout only bounds
  the SSH handshake; the apt sequence itself gets its own budget
  (`UPDATE_TIMEOUT_SECONDS`, default 30 minutes) via arq's `func(...,
  timeout=...)`, distinct from the default job timeout every other
  background job uses. See `app/tasks/worker.py`.
- **Cleanup always runs, chained by `;` not `&&`.** If the upgrade step
  fails, `autoremove`/`autoclean` still run — they're independently
  useful and shouldn't be skipped because of an unrelated upgrade
  problem. The upgrade step's own exit status is still what determines
  whether the run is recorded as succeeded or failed. See
  `app/ssh/updates.py`.
- **`sudo -n` throughout**, never a bare `apt-get` assuming the
  connecting user is root. Non-interactive so a machine without
  passwordless sudo configured fails immediately with a clear error
  instead of hanging on a password prompt that can never be answered
  over a non-interactive SSH exec. See
  [Managed Machine Requirements](Managed-Machine-Requirements.md) for the
  sudoers line this expects.
- **Every run is a row, not just a Redis job.** `MachineUpdateRun`
  persists status/output/error/timestamps in Postgres — arq's own result
  storage is Redis-backed with a TTL and isn't a domain record, so it's
  not what the UI's run-detail and batch pages are built on. A `batch_id`
  (just a shared UUID, not a foreign key to anything) is the only thing
  connecting the runs from one group/"All machines" trigger — there's no
  separate "batch" table, since a `WHERE batch_id = ...` query is all a
  batch results page ever needs.
- **The scheduler-vs-worker split from facts refresh applies here too.**
  A group/"all" trigger creates every `MachineUpdateRun` row and enqueues
  every job in one request/commit, then returns — it never awaits the
  actual updates inline, for the same reason `refresh_all_machine_facts`
  doesn't: one slow or unreachable machine can't be allowed to hold up
  the others or the triggering request.

### Checking for updates without installing them

"Check for updates now" (`app/ssh/updates.check_updates`) still needs
root — an accurate count means actually refreshing the apt cache
(`apt-get update`), not trusting whatever's already cached — but the
enumeration step after that (`apt list --upgradable`) doesn't. It shares
`run_system_update`'s long timeout (via the same `func(...,
timeout=UPDATE_TIMEOUT_SECONDS)` pattern) and its own periodic sweep,
`check_all_machine_updates`, is the same fan-out-then-reschedule shape as
`refresh_all_machine_facts` — both run on the same
`FACTS_REFRESH_INTERVAL_SECONDS` cadence rather than introducing a
separate config knob for what's conceptually the same kind of periodic
check. A failed check (most commonly: sudo not configured yet) resets the
counts to "unknown" rather than leaving a stale number on screen or,
worse, implying zero updates.

Reboot-required detection is different: it needs no privileges at all
(comparing `uname -r` against the newest installed `linux-image-*`
package via `dpkg`), so it rides along in the regular, unprivileged facts
command instead of the root-requiring update check — see
`app/ssh/facts.py`.

### Power actions: fire-and-forget, double-confirmed, untracked

Reboot and shutdown (`app/ssh/power.py`) are deliberately the simplest
SSH action in the app:

- **No persistent history**, unlike `MachineUpdateRun`. There's nothing
  reliable to report — `shutdown -r/-h now` typically returns almost
  immediately, but the SSH connection can legitimately be torn down
  mid-response the moment the remote actually goes down, and that's
  treated as an expected outcome, not an error, rather than something
  worth recording as a "failure." The existing per-minute reachability
  check already shows the machine going offline (and, for a reboot,
  coming back online) — reusing that instead of inventing a second status
  system.
- **Confirmed twice, deliberately not with two stacked JS `confirm()`
  dialogs** (those get reflexively clicked through). The first step is a
  dedicated page stating exactly what's about to happen to which
  machine/group; the second is typing that machine's or group's exact
  name — checked server-side (`power_action` / `group_power_action` /
  `all_power_action` in the route layer), not just disabled-until-typed
  in the browser. "All machines" has no single name of its own, so it
  uses a fixed phrase (`ALL_MACHINES_CONFIRM_PHRASE = "ALL MACHINES"`)
  instead.
- **Same eligibility rule as updates**: a group/all action silently skips
  any machine without a pinned host key fingerprint (surfaced as a
  skipped-count message), since `open_connection` would refuse those
  anyway.

### Scheduling: reusing actions, not reimplementing them

**Scheduling** (`app.scheduling`) runs an existing action — system update,
update check, reboot, shut down — against a machine, a group, or "All
machines" on a cron expression, instead of a human clicking a button. A few
decisions shaped it:

- **An action registry, not a hardcoded list.** `app.scheduling.actions`
  defines a `ScheduledActionSpec` (key, label, description, optional
  per-action params, and a `run` function) and a `register_action()` call.
  `app.scheduling.builtin_actions.register_builtin_actions()` registers the
  four that exist today by wrapping the same functions the manual
  buttons use (see below) — nothing about the `ScheduledTask` model, the
  scheduler tick, or the "New scheduled task" form needs to change to add a
  future fifth action; it only needs one more `register_action()` call.
  It's idempotent and called from both `app.main` (so the web UI has
  something to list) and `app.tasks.worker` (so the scheduler tick does
  too) — either process can run without importing the other.
- **One shared implementation for "trigger this against N machines".**
  `_trigger_updates` / `_trigger_check_updates` / `_send_power_to_machines`
  used to live only in the machine-groups routes; they moved to
  `app.services.machine_actions` (taking the arq redis pool directly rather
  than a `Request`) so a scheduled run and a human clicking "Update now" on
  a group go through the exact same code path, including the same
  skip-unpinned-machines behavior.
- **A fixed one-minute tick, not a configurable self-rescheduling interval.**
  Unlike the facts/update-check sweeps (`FACTS_REFRESH_INTERVAL_SECONDS`),
  cron expressions are minute-grained by construction, so
  `run_due_scheduled_tasks` runs on a plain fixed `cron(second=0)` — the
  same shape as `ping_all_machines` — rather than needing a new setting.
  Each `ScheduledTask` keeps a denormalized `next_run_at` (computed via
  [`croniter`](https://github.com/kiorky/croniter) on create/edit/enable and
  advanced immediately when the tick fires it), so the tick itself is one
  indexed `WHERE next_run_at <= now` query, not N cron-expression
  evaluations every minute. Advancing `next_run_at` *before* the actual
  action job runs (not after) means a slow-running action can't cause the
  same task to be re-enqueued on the next tick before it has even started.
- **No per-run history — same reasoning as power actions.** A schedule
  firing only records a short `last_run_summary` ("Triggered for 3
  machine(s), 1 skipped.") plus `last_run_at`, not a persisted log of every
  firing. Whatever the action actually does already has its own record
  where that belongs (`MachineUpdateRun` for updates; the reachability
  check for power actions) — a second log of "the schedule fired" would
  just be a shadow of that.
- **Always UTC, no per-schedule timezone.** One less setting, and it matches
  every other timestamp already in the app.
- **Reboot/shutdown are schedulable, and deliberately not re-confirmed at
  fire time.** The double-confirmation UX (see below) is what stops a
  *human* from misclicking; a schedule someone deliberately created and can
  see, edit, and disable at `/scheduling` doesn't need — and can't
  sensibly have — a second confirmation step at 3am. Both are flagged
  `destructive=True` in the registry, which the "New scheduled task" form
  surfaces with a ⚠ next to their label so this is obvious before saving.
- **Target encoding: one `<select>`, not a type radio plus two
  conditionally-relevant pickers.** `app.scheduling.targets.encode_target`/
  `decode_target` fold target type + id into one string (`"all"`,
  `"machine:<uuid>"`, `"group:<uuid>"`) so the form has a single dropdown
  listing "All machines", every group, and every machine — no client-side
  JS needed to hide whichever selector doesn't apply.

### Audit log: IP instead of identity, for now

**Audit** (`app.audit`, `app/db/models/audit_log.py`) records what happened,
its outcome, the source IP, and when — for essentially every mutating
action and every safeguard that blocked one (a typed confirmation that
didn't match, an unpinned host key, a bad self-registration token, a
rejected form). A few decisions:

- **`actor` exists and is `None`, on purpose, until there's a login.**
  There's no user identity anywhere in the app yet (see "Deliberately
  deferred" below), so there's nothing truthful to put there — the column
  is present now so that once authentication lands, entries can start
  carrying a real actor without another migration, rather than recording a
  guess (a cookie value, a hostname) that would look like an identity but
  isn't one. `ip_address` is what stands in for "who" today.
- **One write path, called after the fact, never before.** `app.audit.
  log_event()` is the only thing that creates `AuditLogEntry` rows. It
  commits independently of whatever the caller's own transaction is doing,
  and every call site invokes it *after* its own commit (or, for a
  rejected/failed action, once there's nothing else left to commit) — never
  before — so a logging failure can never roll back the action it
  describes, and a validation failure that persisted nothing else still
  gets its own record. A logging failure is caught and swallowed (logged at
  `ERROR`, not raised) for the same reason: an audit-trail gap is far
  better than a broken update button.
- **Not a foreign key.** `target_type`/`target_id` are plain strings, and
  `target_label` is a snapshot of the target's name *at the time of the
  event* — a machine or group can be renamed or deleted later, and the
  trail has to read sensibly regardless (`app/db/models/machine_update_run.
  py`'s `batch_id` uses the same non-FK pattern for the same reason).
- **Scheduled firings are logged too, with a fixed actor.** `app.scheduling.
  jobs.run_scheduled_task` has no HTTP request (and so no IP) behind it —
  entries it writes use `actor="scheduler (automatic)"` instead, which is
  what distinguishes "this reboot happened because of a schedule" from a
  person's IP address in the log.
- **Routine background sweeps are not logged.** `ping_all_machines` (every
  minute, every machine) and the periodic facts/update-check sweeps would
  flood the log with heartbeats, not audit-worthy events — only a
  human-or-schedule-triggered action (and the safeguard that blocked one)
  gets an entry. The per-machine detail of what actually happened already
  lives in its own record (`MachineUpdateRun`, the reachability check) —
  the audit entry for a *trigger* doesn't duplicate that, it just answers
  "who/what IP asked for this, and when."
- **CSRF rejections aren't logged.** `verify_csrf` runs as a route
  dependency before the route body (and its DB session) even exists — hooking
  an audit write into it is a lower-level change than the rest of this
  feature and was left out of this pass.
- **No pagination cursor beyond offset — this is a first pass**, not a
  compliance-grade tamper-evident log (no hash chaining, no write-once
  storage, no retention policy). Good enough to answer "what happened
  here and from where," not something to point a security audit at yet.

### CSRF protection without sessions

Since there's no login yet, there's no session to hang CSRF protection
off of. Instead, a double-submit cookie pattern is used: a random
`csrftoken` cookie (`SameSite=Strict`, `HttpOnly`) is set on GET requests
that render a form, and the same value must be echoed back as a hidden
field on POST. See `app/core/csrf.py`.

### HTTP security headers

Set unconditionally by the app itself (`app/main.py`), regardless of which
reverse proxy — if any — sits in front of it: a strict
Content-Security-Policy (no inline scripts/styles, no external origins),
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, and a restrictive `Permissions-Policy`.
`Strict-Transport-Security` is added when `APP_ENV=production`. The
bundled Caddy config (see [Reverse Proxy: Caddy](Reverse-Proxy-Caddy.md))
additionally sets its own HSTS header and strips the `Server` header at
the edge.

### Container hardening

The runtime image runs as a non-root user, is built via a multi-stage
Dockerfile (build tools never ship in the final image), and the app's own
port is bound to `127.0.0.1` only — it never listens on a
publicly-reachable interface directly. Postgres and Redis ports aren't
published to the host at all by default.

### Deliberately deferred

- Authentication/authorization for app users (the **Users** tab is a
  placeholder for this) — and, as a direct consequence, *who* performed an
  audited action: the **Audit** log records the source IP and what
  happened today, not an identity (see "Audit log" above).
- Rate limiting at the application layer (a reverse proxy or upstream
  service is expected to handle this today).
- Per-schedule timezones (everything is UTC) and a scheduled "power on" to
  pair with scheduled shutdown (there's no way for the app to power on a
  machine that's off — see [Managed Machine
  Requirements](Managed-Machine-Requirements.md)).
