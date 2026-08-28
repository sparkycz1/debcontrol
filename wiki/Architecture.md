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
  placeholder for this).
- An audit log of actions taken against managed machines.
- Rate limiting at the application layer (a reverse proxy or upstream
  service is expected to handle this today).
