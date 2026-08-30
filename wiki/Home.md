# 📚 debcontrol wiki

debcontrol is a web application for managing Debian machines over SSH —
officially, Debian and its derivatives (e.g. Ubuntu), for as long as each
is supported by its own upstream. Every page requires a login; access is
controlled by custom RBAC roles,
and accounts can be local, LDAP, or OIDC (SSO), with optional TOTP
two-factor — see [Architecture](Architecture.md#authentication--rbac) for
the design and [Installation](Installation.md) for bootstrapping the first
admin account. A light/dark theme toggle is in the header next to your
account link; the choice is remembered in a cookie, dark by default.

## 📑 Pages

- **[Installation](Installation.md)** — Docker quick start, running with or
  without the bundled Caddy reverse proxy, environment variables reference.
- **[Architecture](Architecture.md)** — technology choices, project
  structure, and the security decisions made from day one.
- **[SSH Host Key Verification](SSH-Host-Key-Verification.md)** — how
  debcontrol pins SSH host keys and why it never "trusts on first use".
- **[Managed Machine Requirements](Managed-Machine-Requirements.md)** —
  what a Debian machine needs (network, account, packages) to be added.
- **[Ansible Onboarding](Ansible-Onboarding.md)** — a playbook that does
  everything in Managed Machine Requirements for you, then self-registers
  the machine as pending.
- **[AI Assistant](AI-Assistant.md)** — the chat assistant: the five
  supported providers, the global token limits, the permission model, and
  the confirm-before-execute rule that every proposed action goes through.
- **[Development](Development.md)** — running the app locally without
  Docker, tests, linting, and database migrations.

> [!NOTE]
> debcontrol runs as **three application processes**: the FastAPI **web**
> app, a **Celery worker** that performs every SSH/background operation, and
> a single **Celery Beat** scheduler that publishes the periodic sweeps and
> the per-minute scheduled-task tick. Redis is both Celery's broker and its
> result backend. See
> [Architecture → Background tasks](Architecture.md#background-tasks-celery-and-celery-beat).

## 🔒 Reverse proxy guides

debcontrol itself only speaks plain HTTP, on port `8080` by default
(`APP_PORT` in `.env`) — it always expects to sit behind a
TLS-terminating reverse proxy, though nothing stops direct access unless
you firewall that port off. Pick one:

- **[Caddy (bundled)](Reverse-Proxy-Caddy.md)** — the easiest path:
  `docker-compose.caddy.yml` gives you automatic HTTPS (Let's Encrypt),
  TLS 1.3 only, and HTTP/3 with no manual certificate handling.
  Also useful if you'd rather run your own separate Caddy instance.
- **[nginx](Reverse-Proxy-Nginx.md)** — if you already run nginx for other
  sites on this host.
- **[Traefik](Reverse-Proxy-Traefik.md)** — if you already run Traefik
  (e.g. alongside other Docker Compose projects).

## ✨ Feature overview

| Tab | Status |
|---|---|
| Dashboard | Post-login landing page: machine/update/reboot counts, upcoming scheduled tasks, recent audit activity — each section only shown if your role can see that area; once at least two days of history exist, dependency-free inline SVG trend chart(s) (online machines, pending updates) built from a daily background snapshot, retention configurable on Settings |
| Machines | Add/view/edit/remove managed machines, pin host keys, test connectivity, auto-discovered facts (OS, kernel, CPU architecture/cores, RAM, disks, filesystem usage, network interfaces, uptime, process count, reboot-required), installed packages (apt/flatpak/snap, with versions and held/pinned status, searchable) plus a fleet-wide package search across every machine, online/offline status, self-registration review (incl. via the [Ansible playbook](Ansible-Onboarding.md)), CSV bulk import (pending queue), free-text search, system updates (apt + flatpak + snap) with dry-run update checks that also list *which* packages are pending, a preview-and-confirm step before a manual single-machine update run that shows exactly what would be installed/upgraded/removed, a paginated/filterable full update-run history per machine, reboot/shutdown (double-confirmed) — all three also available as bulk actions on an ad-hoc checkbox selection, not just per-machine or per-group; machine/group configuration export (JSON or CSV) and import (JSON), deliberately excluding credentials and pinned host keys; an interactive SSH terminal in the browser (permission-gated, audited, session-capped) |
| Machine groups | Organize machines into named groups; built-in "All machines" group; the group list itself is searchable, and each group's members are separately searchable; system updates, update checks, and power actions all scoped to a group |
| Scheduling | Run any existing action (system update, update check, reboot, shut down) against a machine, a group, or "All machines" on a cron expression (UTC); enable/disable, run on demand, see when it last fired |
| AI | A chat assistant (five configurable providers: Anthropic, OpenAI, Gemini, OpenRouter, or any OpenAI-compatible endpoint) that can look up machines/groups on its own and *propose* updates, update checks, reboots/shutdowns, or an SSH command — every one of which needs an explicit human confirmation showing the literal command and every resolved target before anything runs; gated by `ai.access` plus, per tool, the same permission the equivalent manual button needs; global rolling daily/weekly/monthly token limits. See [AI Assistant](AI-Assistant.md) |
| Audit | Read-only log of every mutating action across the app — who (account + source IP), what happened, its outcome, and when; searchable and filterable by outcome; hash-chained so tampering is detectable; exportable as CSV/JSON; optional live syslog forwarding (e.g. to a SIEM) |
| Users | Create/edit/deactivate/delete accounts; assign a role; login method (local/LDAP/OIDC) is per-account; grant/revoke API access (a separate checkbox from role permissions); optionally restrict an account to specific machine groups (unchecked = full access); reset a local password; force sign-out |
| Roles | Define named roles with an exact permission checkbox matrix; guardrails prevent locking everyone out of user management; a role can require TOTP two-factor for everyone holding it, enforced live on every request |
| My account | Change your own password, enroll/disable TOTP two-factor with recovery codes, log out everywhere else, create/revoke your own API tokens (if an admin has granted this account API access) for the full read/write REST API |
| API docs (`/api`) | Interactive [Swagger UI](https://swagger.io/tools/swagger-ui/) for the full REST API, generated live from the app's own routes — browse every endpoint, and use **Authorize** with one of your own API tokens to try requests directly from the page; requires being logged in like any other page (see [Architecture](Architecture.md#interactive-docs-swagger-ui-at-api)) |
| Settings | Shows the running version/git commit, the app's SSH public key and background-check intervals, supports rotating the SSH key (generate/activate a replacement, with an assisted "push pending key to all machines" step); sets the audit log retention policy, verifies hash-chain integrity, exports the audit log (CSV/JSON), sets the Dashboard trend snapshots' retention policy, configures syslog forwarding (UDP/TCP/TLS), configures LDAP/OIDC login, and configures the [AI assistant](AI-Assistant.md) (per-provider API key, fetch and opt-in individual models, global rolling token limits) |
