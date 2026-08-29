# debcontrol wiki

debcontrol is a web application for managing Debian machines over SSH —
officially, Debian and its derivatives (e.g. Ubuntu), for as long as each
is supported by its own upstream. Every page requires a login; access is
controlled by custom RBAC roles,
and accounts can be local, LDAP, or OIDC (SSO), with optional TOTP
two-factor — see [Architecture](Architecture.md#authentication--rbac) for
the design and [Installation](Installation.md) for bootstrapping the first
admin account.

## Pages

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
- **[Development](Development.md)** — running the app locally without
  Docker, tests, linting, and database migrations.

## Reverse proxy guides

debcontrol itself only speaks plain HTTP on `127.0.0.1:8000` — it always
expects to sit behind a TLS-terminating reverse proxy. Pick one:

- **[Caddy (bundled)](Reverse-Proxy-Caddy.md)** — the easiest path:
  `docker-compose.caddy.yml` gives you automatic HTTPS (Let's Encrypt),
  TLS 1.3 only, and HTTP/3 with no manual certificate handling.
  Also useful if you'd rather run your own separate Caddy instance.
- **[nginx](Reverse-Proxy-Nginx.md)** — if you already run nginx for other
  sites on this host.
- **[Traefik](Reverse-Proxy-Traefik.md)** — if you already run Traefik
  (e.g. alongside other Docker Compose projects).

## Feature overview

| Tab | Status |
|---|---|
| Dashboard | Post-login landing page: machine/update/reboot counts, upcoming scheduled tasks, recent audit activity — each section only shown if your role can see that area |
| Machines | Add/view/edit/remove managed machines, pin host keys, test connectivity, auto-discovered facts (OS, kernel, CPU architecture/cores, RAM, disks, uptime, process count, reboot-required), installed packages (apt/flatpak/snap, with versions, searchable), online/offline status, self-registration review (incl. via the [Ansible playbook](Ansible-Onboarding.md)), CSV bulk import (pending queue), free-text search, system updates (apt + flatpak + snap) with dry-run update checks that also list *which* packages are pending, reboot/shutdown (double-confirmed) |
| Machine groups | Organize machines into named groups; built-in "All machines" group; search, system updates, update checks, and power actions all scoped to a group |
| Scheduling | Run any existing action (system update, update check, reboot, shut down) against a machine, a group, or "All machines" on a cron expression (UTC); enable/disable, run on demand, see when it last fired |
| Audit | Read-only log of every mutating action across the app — who (account + source IP), what happened, its outcome, and when; searchable and filterable by outcome; hash-chained so tampering is detectable; exportable as CSV/JSON; optional live syslog forwarding (e.g. to a SIEM) |
| Users | Create/edit/deactivate/delete accounts; assign a role; login method (local/LDAP/OIDC) is per-account; reset a local password; force sign-out |
| Roles | Define named roles with an exact permission checkbox matrix; guardrails prevent locking everyone out of user management |
| My account | Change your own password, enroll/disable TOTP two-factor with recovery codes, log out everywhere else, create/revoke your own API tokens |
| Settings | Shows the running version/git commit, the app's SSH public key and background-check intervals, supports rotating the SSH key (generate/activate a replacement); sets the audit log retention policy, verifies hash-chain integrity, exports the audit log (CSV/JSON), configures syslog forwarding (UDP/TCP/TLS), and configures LDAP/OIDC login |
