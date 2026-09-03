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

```mermaid
flowchart LR
    App(("debcontrol"))
    App --> Dash["Dashboard"]
    App --> M["Machines"]
    App --> G["Machine groups"]
    App --> Sched["Scheduling"]
    App --> AI["AI assistant"]
    App --> Audit["Audit log"]
    App --> Set["Settings"]
    M --> M1["Overview · Monitoring · Updates<br/>Terminal · Logs · Power · Settings"]
```

## 📑 Pages

- **[Installation](Installation.md)** — Docker quick start, running with or
  without the bundled Caddy reverse proxy, environment variables reference.
- **[Architecture](Architecture.md)** — technology choices, project
  structure, and the security decisions made from day one.
- **[Host Requirements](Host-Requirements.md)** — sizing
  debcontrol's own host(s) for a fleet from dozens to thousands of
  machines, and the tuning knobs (worker concurrency, DB pool size,
  reachability-sweep concurrency, retention policies) that come with it.
- **[SSH Host Key Verification](SSH-Host-Key-Verification.md)** — how
  debcontrol pins SSH host keys and why it never "trusts on first use".
- **[Machine Requirements](Machine-Requirements.md)** —
  what a Debian machine needs (network, account, packages) to be added.
- **[Ansible Onboarding](Ansible-Onboarding.md)** — a playbook that does
  everything in Machine Requirements for you, then self-registers
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
| Dashboard | Post-login landing page: machine/update/reboot counts, upcoming scheduled tasks, recent audit activity — each section only shown if your role can see that area; once at least two days of history exist, dependency-free inline SVG trend chart(s) (online machines, pending updates) built from a daily background snapshot, retention configurable on Settings; an optional AI-written **fleet summary** ("what changed, what needs attention" — see [AI Assistant](AI-Assistant.md)) if an admin has turned it on |
| Machines | A machine's page is split into tabs — Overview, Monitoring, Updates, Terminal, Logs, Power, Settings (Terminal/Logs only shown with `action.terminal`). Overview: edit/remove, pin host keys, test connectivity, an OS logo badge next to the name, auto-discovered facts (OS, kernel, CPU architecture/cores/model, RAM (+speed where readable), disks, filesystem usage, network interfaces, uptime, process count, reboot-required), installed packages (apt/flatpak/snap, with versions and held/pinned status, searchable) plus a fleet-wide package search across every machine, online/offline status, and a banner if the post-onboarding readiness check (ncurses-term, scoped sudo for apt/shutdown/dmidecode/flatpak+snap) found something missing, with a one-time-credential "Fix it" flow for a machine already on the app's own SSH key; facts, packages, and services each have a manual **Refresh now** button that waits for the result inline instead of waiting for the next periodic sweep; status/facts/packages/services panels also update live over a WebSocket the moment a background refresh finishes, rather than waiting out their own polling interval. Monitoring: CPU/RAM, load average (1/5/15 min), per-interface network throughput, and per-disk I/O throughput sampled every couple of minutes, each as an interactive hover/scrub trend chart with a real time axis; a live failed-systemd-service count and a searchable/filterable full service list in a modal — both the sample interval and its retention are configurable globally and per machine. Updates: system updates (apt + flatpak + snap) with dry-run update checks that also list *which* packages are pending, a preview-and-confirm step before a manual update run that shows exactly what would be installed/upgraded/removed and streams apt's output live once it's running, a paginated/filterable full update-run history. Terminal: an interactive SSH shell in the browser (256-color, clipboard copy/paste, permission-gated, audited, session-capped). Logs: the systemd journal (search, line limit, `--since`/`--until`) or one file under a configurable allowed-path list — a live SSH view every time, never stored. Power: reboot/shutdown (double-confirmed). Settings: edit connection details, per-machine overrides of every background-check interval and the monitoring retention window, delete the machine, and (for a machine still on password auth) **Run initial setup** — creates a dedicated user, installs debcontrol's own SSH key, and grants scoped sudo directly over SSH, the same steps the [Ansible playbook](Ansible-Onboarding.md) automates for someone who'd rather run that instead. Also: self-registration review, CSV bulk import (pending queue), free-text search, filtering by **tag** (free-form labels independent of groups — a machine can carry any number, set from the create/edit form or the REST API, with autocomplete over every tag already in use), bulk update/check/power actions on an ad-hoc checkbox selection, machine/group configuration export (JSON or CSV) and import (JSON, tags included) deliberately excluding credentials and pinned host keys |
| Machine groups | Also split into tabs — Overview, Updates, Power. Organize machines into named groups; built-in "All machines" group; the group list itself is searchable, and each group's members are separately searchable; system updates, update checks, and power actions all scoped to a group |
| Scheduling | Run any existing action (system update, update check, reboot, shut down, or an arbitrary custom command — that one needs `action.terminal` in addition to `scheduling.manage`, and runs as the target machine's own configured SSH user, which needs whatever permission the command itself requires) against a machine, a group, or "All machines" on a cron expression (UTC); enable/disable, run on demand, see when it last fired |
| AI | A chat assistant (five configurable providers: Anthropic, OpenAI, Gemini, OpenRouter, or any OpenAI-compatible endpoint), shown as a proper back-and-forth conversation that updates live while a reply is in progress, that can look up machines/groups on its own and *propose* updates, update checks, reboots/shutdowns, or an SSH command — every one of which needs an explicit human confirmation showing the literal command and every resolved target before anything runs; gated by `ai.access` plus, per tool, the same permission the equivalent manual button needs; a searchable model picker and global rolling daily/weekly/monthly token limits on the Settings AI tab. A one-click **"Ask AI why"** button on a failed update run and on a machine's readiness banner starts a new conversation pre-filled with that failure/finding — nothing to type or copy-paste. See [AI Assistant](AI-Assistant.md) |
| Audit | Read-only log of every mutating action across the app — who (account + source IP), what happened, its outcome, and when; searchable and filterable by outcome; hash-chained so tampering is detectable; exportable as CSV/JSON; optional live syslog forwarding (e.g. to a SIEM) |
| Users | Create/edit/deactivate/delete accounts; assign a role; login method (local/LDAP/OIDC) is per-account; grant/revoke API access (a separate checkbox from role permissions); optionally restrict an account to specific machine groups (unchecked = full access); reset a local password; force sign-out |
| Roles | Define named roles with an exact permission checkbox matrix; guardrails prevent locking everyone out of user management; a role can require TOTP two-factor for everyone holding it, enforced live on every request |
| My account | Change your own display name, password, and UI language (English by default; more languages installable by an admin, see [Architecture](Architecture.md#per-user-ui-language-i18n)), enroll/disable TOTP two-factor with recovery codes, log out everywhere else, create/revoke your own API tokens (if an admin has granted this account API access) for the full read/write REST API |
| API docs (`/api`) | Interactive [Swagger UI](https://swagger.io/tools/swagger-ui/) for the full REST API, generated live from the app's own routes — browse every endpoint, and use **Authorize** with one of your own API tokens to try requests directly from the page; requires being logged in like any other page (see [Architecture](Architecture.md#interactive-docs-swagger-ui-at-api)) |
| Settings | Split into tabs — General, Security, Integrations, AI. General: running version/git commit, the app's SSH public key, background-check intervals, rotating the SSH key (generate/activate a replacement, with an assisted "push pending key to all machines" step). Security: audit log retention policy, hash-chain verification and CSV/JSON export, Dashboard trend snapshots' retention policy, update-run history retention policy, Monitoring history retention policy. Integrations: syslog forwarding (UDP/TCP/TLS), LDAP login, OIDC login. AI: configures the [AI assistant](AI-Assistant.md) (per-provider API key, fetch and opt-in individual models, global rolling token limits, and the opt-in scheduled fleet summary — frequency, which model, retention) |
