# 🖥️ Machine Management

*Everything about a managed machine once it's added: host keys, secrets,
updates, facts, monitoring, Proxmox, Docker, checks, logs, live updates,
tags, bulk actions, power, the terminal and scheduling. See
[Architecture](Architecture.md) for the rest (auth/RBAC, audit log,
notifications, HTTP hardening).*

## Access and trust

### 🔑 SSH host key pinning

See [SSH Host Key Verification](SSH-Host-Key-Verification.md). Nothing
connects to a machine whose host-key fingerprint a human hasn't
confirmed, and a later mismatch hard-fails instead of reconnecting.

### Secrets at rest

Machine passwords, the app's SSH private key, TOTP secrets and every
third-party credential (AI providers, LDAP/OIDC, SMTP, push tokens) are
encrypted in Postgres with **AES-256-GCM** (`app.core.security`), keyed by
`ENCRYPTION_KEY`, which lives only in the environment. This protects
against a database-only leak (a backup, a replica); it doesn't replace
authentication.

### FIPS alignment

debcontrol isn't FIPS-*certified* — that needs a NIST-validated crypto
module, a build/deployment choice (base image, OpenSSL build). It only
uses FIPS-approved algorithms, so certification is a module swap:

- secrets: AES-256-GCM (legacy Fernet values still decrypt;
  `scripts/reencrypt_secrets.py` upgrades them);
- signed tickets (pending TOTP, WebAuthn challenge): HMAC-SHA-256;
- session tokens and host-key fingerprints: SHA-256;
- SSH to machines: NIST-curve ECDH or ≥2048-bit DH with SHA-2,
  AES-GCM/CTR, HMAC-SHA-2 — not applied to host-key discovery or the
  accepted host-key algorithm (the key is pinned by fingerprint);
- TOTP and WebAuthn use approved algorithms already.

**One deliberate exception: Argon2id** for password hashing. SP 800-132
only approves PBKDF2, but Argon2id is memory-hard and far more
GPU-resistant — a real security gain kept over the checkbox.

### One shared SSH identity, not one key per machine

debcontrol generates one ed25519 keypair and uses it wherever "SSH key" is
the auth method; the private half is only decrypted in memory. The public
half is on **Settings**. Per-machine passwords remain a fallback.

**Rotation** is staged so the app is never locked out: *Generate
replacement key* creates a pending key; *Push pending key to all machines*
appends it to every pinned SSH-key machine's `authorized_keys` using the
current key; *Activate* swaps it in; *Discard pending key* throws it away.
Web-only on purpose.

### Self-registration is not the same as trust

`POST /api/inform` (bearer `INFORM_TOKEN`, for a first-boot/cloud-init
script — see [Machine Requirements](Machine-Requirements.md)) only
creates a `PendingMachine` for a human to review. Turning it into a
`Machine` still goes through the add form and host-key confirmation.
`ansible/debcontrol-onboard.yml` prepares the account, key and sudoers
first and makes the same call — see [Ansible Onboarding](Ansible-Onboarding.md).

### Post-onboarding readiness check

**Settings** shows a banner when `app.ssh.readiness` finds something
missing (ncurses-term, scoped `sudo -n` for apt/shutdown/dmidecode,
flatpak/snap). It runs after host-key confirmation, after onboarding, on
demand and on the facts cadence, so a grant removed later is caught too.
A `root` account never lacks sudo; only ncurses-term can be missing, and
*Install now* fixes it. For a non-root machine the banner shows the exact
sudoers line (the same `app.ssh.onboarding.SUDO_COMMANDS` list onboarding
writes), and *Fix it* can apply it with a one-time root login that is
never stored.

## Updates

### System updates

`apt-get update` → the chosen strategy → `autoremove` → `autoclean`, plus
flatpak/snap when installed (**Machines → a machine → Updates**, a group,
or *All machines*; `action.updates`).

- **Strategies**: `full_upgrade` (default, what Proxmox recommends),
  `upgrade` (never removes/installs — such updates are held back),
  `security` (only packages from a `*-security` suite). `dist_upgrade` is
  still accepted as an alias.
- **Timeout**: `AppSettings.update_timeout_seconds` (Settings → Checks &
  retention, default 30 min).
- Cleanup always runs (`;`-chained); the upgrade's exit status decides
  success. Everything runs through `sudo -n`, so a missing grant fails
  fast instead of hanging.
- Every run is a `MachineUpdateRun` row (status, output, timestamps);
  runs triggered together share a `batch_id`. Group/fleet triggers create
  every row and enqueue one task per machine, then return.
- Output is written every ~2 s and shown in a fixed-height box that
  follows the end while live and keeps your place when you scroll up
  (`static/js/run-output.js`). Scripts poll
  `GET /api/v1/machines/{id}/update-runs/{run_id}`.

**Preview.** *Run update* first shows a dry run (`apt-get -s`): what would
be installed, upgraded and **removed**. Only *Confirm* runs it. The REST
API keeps a direct trigger.

**Rollback.** Each run stores a `dpkg-query` snapshot before upgrading.
`POST /machines/{id}/updates/{run_id}/rollback` (`action.updates`)
creates a new run that re-installs only the packages that changed since
that snapshot, at their old versions (`--allow-downgrades`; the old
`.deb` must still be available). Rolling back a rollback is refused.

**Hold, changelog, reboot hints.**

- *hold* / *release* per package (`apt-mark`), audited as
  `machine.package.hold` / `.unhold`; REST `POST`/`DELETE
  /api/v1/machines/{id}/packages/{name}/hold`.
- *changelog* shows what changed since the installed version, fetched live
  (`GET /api/v1/machines/{id}/packages/{name}/changelog`).
- Kernel, microcode, firmware, `libc6`, `systemd`, `dbus` and Proxmox core
  packages carry a reboot/restart hint. "Reboot required" also counts
  Proxmox kernels and `/run/reboot-required`.

### Checking for updates

*Check for updates now* (and the periodic sweep, on the facts cadence)
runs `apt-get update` + `apt list --upgradable`, plus `flatpak remote-ls
--updates` and `snap refresh --list` when present. The result is stored
per machine as the package list with current and new versions; a failed
check shows "unknown", not a stale number. flatpak/snap counts are
separate fields (`flatpak_upgradable_count`, `snap_upgradable_count`).

### Security updates and the CVEs they fix

Packages from a `*-security` suite are flagged, and for each the **CVE
ids and urgency** are read from `apt-get changelog` *on the machine* — no
CVE database, nothing sent from the server (`app/ssh/security_advisories.py`;
at most 15 new lookups per check, 20 s each).

The Updates tab lists them first with CVE links. **Security → Security
updates** (`/security/updates`, `machine.view`) groups every pending
security update across the visible fleet, most urgent first — REST
`GET /api/v1/machines/security-updates`. Newly pending security updates
fire `machine.security_updates` and appear on the History tab.

## Inventory

### Facts gathered

One unprivileged SSH round trip (`app/ssh/facts.py`) on the facts cadence,
or on demand with Overview's **Refresh now** (`POST
/machines/{id}/refresh-facts`, `machine.manage`): OS and kernel, CPU
architecture and model, uptime, process count, filesystems (`df`), IPv4
addresses, listening TCP ports (`ss -Htln`), admin and login accounts
(from `/etc/group` and `/etc/passwd`, never `getent`), and physical vs.
virtual (`systemd-detect-virt` → `Machine.is_physical`, which gates the
hardware probes).

### Configuration drift

Each facts refresh diffs hostname, OS, kernel, CPU cores, RAM, disks,
mounts, IPs, listening ports and accounts (`app/services/config_drift.py`).
Each difference becomes a `MachineChange` on the **History** tab and one
`machine.config_changed` notification lists them. A previously unknown
value isn't a change, so upgrades don't flood anyone. Not audited (it's a
sweep). **Machines → Status → Configuration changed (7 days)** filters
for it.

### Installed packages and services

- **Packages**: one `MachinePackage` row per package (dpkg, flatpak,
  snap), replaced as a whole on each refresh and after every update run.
  **Security → Package search** (`/security/packages`) finds a package
  across the fleet (up to 500 rows).
- **systemd services**: one `MachineService` row per unit, on the same
  cadence, shown on the Monitoring tab (running and failed by default)
  and at `GET /api/v1/machines/{id}/services`. Running units also carry
  CPU (average since the previous snapshot, and peak) and memory (current
  and peak) from their cgroup accounting; `N/A` when unavailable.

### Export and import

- **Inventory CSV** — *More actions → Export inventory*
  (`GET /machines/inventory.csv`): every machine matching the list's
  filter with status, OS, hardware, updates and timestamps. Audited as
  `machine.inventory_export`. JSON: `GET /api/v1/machines`.
- **Machine/group config** (`app.services.machine_config`, web and API):
  structural only — never secrets or host keys. Password-auth machines
  come back as `ssh_key` and are listed so credentials can be revisited;
  every imported machine starts unpinned. Existing names are skipped,
  existing groups reused.
- **Roles** and **scheduled tasks** export/import the same way (skipping
  existing names; a scheduled task whose target or action doesn't resolve
  is skipped, and import obeys the importer's scope and permissions).

### Runbook, notes and History

- **Runbook** — a Markdown field (up to 20 000 chars) rendered on
  Overview with `mistune` and `escape=True` (raw HTML becomes text,
  `javascript:` links are dropped). Part of config export and the API.
- **History** (`/machines/{id}/history`, `machine.view`) merges notes,
  detected changes, update runs, reachability outages and — for
  `audit.view` accounts — audited actions, newest first (24 h to 1 year,
  up to 300 events). **Notes** need `machine.manage` and are audited
  (`machine.note.add` / `.delete`). *Summarize with AI* (`ai.access`)
  starts an assistant conversation from the visible time line. REST:
  `GET /api/v1/machines/{id}/timeline`, `POST/DELETE
  /api/v1/machines/{id}/notes`.

## Monitoring

### Samples, charts and history

A monitoring sample every `MONITORING_INTERVAL_SECONDS` stores CPU, load,
RAM, disk and network counters and filesystem usage
(`MachineMonitoringSample`, purged by the monitoring retention setting or
a per-machine override). The **Monitoring** tab shows two columns of
charts: CPU, memory, disk usage and I/O, network, load, availability and
connect latency, then Docker, hardware, S.M.A.R.T. and systemd services.

- Charts are server-rendered SVG (`app/web/charts.py`, CSP-safe);
  `static/js/monitoring-chart.js` adds tooltips, legend toggles and table
  filter/sort. A condition-based notification's threshold is drawn as a
  dashed line.
- Virtual network interfaces and secondary sensors start hidden (one click
  away in the legend).
- JSON: `GET /api/v1/machines/{id}/monitoring?range_key=1h|24h|7d|30d|90d`;
  *Refresh now*: `POST /api/v1/machines/{id}/monitoring/refresh`.

**Availability** comes from the per-minute reachability sweep (a TCP
connect to the SSH port, not ICMP), historized as
`MachineReachabilitySample` — written on success *and* failure, so
outages are visible.

**Disk-full forecast.** Hourly, a least-squares line through each mount's
last 7 days (`app/services/disk_forecast.py`) gives "full in ~N days",
shown on the Disk usage card, in the API (`/hardware`) and usable as the
`monitoring.disk_full_days` notification condition.

### Hardware (bare metal only)

When `is_physical`, each sample also reads: temperatures and fans
(`sensors -j`), S.M.A.R.T. health (`smartctl -H`, needs a sudoers grant),
CPU power (Intel/AMD RAPL counters) and GPUs (NVIDIA via `nvidia-smi`,
AMD/Intel via sysfs — utilization, VRAM, power). Devices appearing or
disappearing are simply reflected in the next sample. Full S.M.A.R.T.
detail (`smartctl -a -j` per disk) is refreshed with facts
(`Machine.smart_devices`). REST: `GET /api/v1/machines/{id}/hardware`.

**Memory on a ZFS host**: the ARC is excluded from *Used* (it's reclaimable)
and stacked separately on the chart; alert thresholds apply to *Used*.

### Keeping the journal quiet

- **Connection reuse** (`app.ssh.pool`): periodic collectors run over one
  cached SSH connection per machine per worker process instead of a new
  login each time. A cached connection is used only if address, account,
  host key and credential still match. Idle ones close after **Settings →
  Checks & retention → Keep SSH connections open** (default 15 min; 0 =
  always log in). Updates, power, the terminal and logs use their own
  connection.
- **No `sudo` for root** (`app.ssh.shell.with_root_shim`): as root,
  `sudo -n …` runs directly, so no sudo/PAM lines per sample.

### Machine cards on the Dashboard

The Dashboard's bottom section (`/fleet` redirects to `/dashboard#fleet`)
shows every visible, active machine as a card: CPU, RAM, fullest
filesystem, hottest sensor, load, uptime, containers, pending (security)
updates, reboot and disk-full flags. The border takes the worst reading's
color (warn 75 %, danger 90 %; temperature 70/85 °C). The tiles above link
to the Machines list filtered by the same status. Refreshed every 60 s,
up to 500 machines. REST: `GET /api/v1/fleet`.

## Proxmox VE, Backup Server, Mail Gateway and ZFS

A **Proxmox** tab appears on a Proxmox VE, Backup Server or Mail Gateway
host (a plain ZFS host gets it as **ZFS**); Overview starts with a
one-line summary linking to it, and the OS reads e.g. "Proxmox Backup
Server 3.2.7 (Debian …)". Everything rides on existing round trips
(`app.ssh.proxmox`).

- **VE — every monitoring sample**: ZFS pools (health, use, last scrub,
  errors), every VM/container (state, CPU, memory, uptime, node, tags) and
  cluster quorum with online nodes.
- **VE — every facts refresh**: version, storages, backup jobs, recent
  vzdump results, guests no backup job covers, recently failed tasks.
- **Guest actions** (`action.power`): *start*, or *shut down* / *reboot* /
  *stop* (confirmed) via `pvesh create
  /nodes/<node>/<qemu|lxc>/<vmid>/status/<action>`, with node, type and
  VMID from the latest sample, strictly validated. Audited as
  `machine.guest.<action>`; REST `POST
  /api/v1/machines/{id}/proxmox/guests/{vmid}/{action}`.
- **Backup Server** (facts, `proxmox-backup-debug api get`): datastores
  with usage and estimated full date; GC/verify/sync/prune jobs (failures
  flagged); backup groups with last backup (older than 2 days highlighted);
  recent tasks.
- **Mail Gateway** (facts, `pmgsh`): mail in the last 24 h (in, out, spam,
  viruses, rejects, bounces), the Postfix queue (warning at 50
  deferred/held) and ClamAV signatures.

The tools run through `sudo -n` (a no-op for root); onboarding grants
them. REST: `GET /api/v1/machines/{id}/proxmox` (`product`, `cluster`,
`failed_tasks`, `backup_server`, `mail_gateway`, and the VE data).

## Docker containers

Any machine with a `docker` CLI gets a Docker section in each sample —
plain `docker` (account in the `docker` group) or `sudo -n docker`
(onboarding grants it when Docker is installed; that is root-equivalent,
like the `apt-get` grant). Without access, the tab explains how to grant
it. Stats come from `docker ps -a` / `docker stats`, network bytes from
each container's own `/proc/<pid>/net/dev`.

- **Actions** (`action.power`): *Start*, *Stop*, *Restart* per container,
  confirmed; name and action validated before anything runs; audited as
  `machine.container.<action>`. REST
  `POST /api/v1/machines/{id}/containers/{name}/{action}`.
- **Image updates**: daily at 04:30 and on demand (*Check image updates*,
  `machine.manage`), each running image's digest is compared with the
  registry's (`docker buildx imagetools inspect`, nothing pulled). Detection
  only; `docker.image_updates_count` can drive a notification.

## Endpoint checks

**Checks** (`/checks`; `machine.view` to see, `machine.manage` to change or
*Run now*) run from the debcontrol server, independent of machines:

- **HTTP** — GET with redirects; up when the status matches (or < 400) and
  the optional *must contain* / *must not contain* / JSON path assertions
  hold (first 1 MB of the body). https also reports certificate expiry.
- **TLS** — handshake and certificate expiry (verification optional).
- **Ping** (unprivileged ICMP socket), **TCP** (`host:port`), **DNS**
  (`name` or `name@resolver`, optionally an expected address).
- Optional **maximum response time**.

Beat enqueues due checks every minute (interval 30 s–1 day). Each probe is
stored; a check's page shows uptime, average/p95 latency and charts
(`GET /api/v1/checks/{id}/history`). Notifications: `endpoint.down` after 2
consecutive failures, `endpoint.recovered`, `endpoint.cert_expiring`.

**SLA report** (`/checks/sla`, CSV, `GET /api/v1/checks/sla?month=YYYY-MM`):
per check and per visible machine — availability %, estimated downtime,
outages and whether the optional SLA target was met.

REST: `GET/POST /api/v1/checks`, `PUT/DELETE /api/v1/checks/{id}`,
`POST /api/v1/checks/{id}/run`.

## Logs

**Logs** (`action.terminal`, not `machine.view` — reading logs is a higher
trust level) is a live SSH read on every view; nothing is stored, only
that a view happened is audited. Sources: the **journal**, **one file**
under the `LOG_FILE_ALLOWED_PATHS` allowlist (typed or browsed), or **one
Docker container**.

- Journal filters: **priority** (`-p`), **unit** (`-u`), **boot** (`-b 0`
  … `-20`), search, since/until. Lines are colored by their real priority
  (`journalctl -o json`).
- **Hide debcontrol's own sessions** drops the sshd/logind/sudo lines
  debcontrol's own logins cause, matched on journald fields.
- **Saved log views** (per account, offered on every machine); REST
  `GET/POST /api/v1/account/saved-log-views`.
- **Follow live** streams over a WebSocket (`journalctl -f`, `tail -F`,
  `docker logs -f`), authenticated like the terminal, capped at one hour,
  audited as `machine.logs.follow` / `.follow_end`. Web-only.
- REST snapshot: `GET /api/v1/machines/{id}/logs`.

## Live updates: a WebSocket doorbell

Background jobs publish `{"kind": "facts" | "packages" | "services" |
"updates" | "status"}` to a per-machine Redis channel after committing
(`app/services/live_updates.py`); `/machines/{id}/live/ws` relays it
(`machine.view`, same hand-rolled auth as the terminal); `live-updates.js`
turns it into a `live-<kind>` event the htmx panels listen for, and they
re-fetch through their normal permission-checked endpoint. No machine
data is pushed. Panels still poll every 60 s as a fallback. Opt-in
**browser notifications** fire for these events while the tab is in the
background (client-side only, no push service).

## Machine list

### Tags, filters and saved views

- **Tags**: any number per machine, independent of the single group;
  normalized (lowercase, trimmed, ≤ 64 chars), created on first use and
  deleted when unused (`app.services.machine_tags`). The search box also
  matches tags; `?tag=a&tag=b&tag_mode=and|or` filters by several.
- **Filters**: status (offline, updates, security, reboot, configuration
  changed, host key unconfirmed) and group — the same on
  `GET /api/v1/machines?status=&group=` (ordered by name; `limit`/`offset`
  page through a large fleet) and the CSV inventory.
- **Saved views**: per account, only known parameters are stored
  (`build_query_string`). REST `GET/POST /api/v1/account/saved-views`.
- **Display modes**: Table / List / Cards (a per-browser cookie). Cards
  show each machine's latest CPU/RAM from one batched query.

### Bulk actions

Selected machines can be updated, checked for updates, rebooted or shut
down through the same `machine_actions` functions as groups (power needs
the typed phrase `SELECTED MACHINES`). **Move to group** (`machine.manage`)
respects the account's scope and is audited as `machines.bulk.group.assign`.
Bulk tag add/remove is API-only (`POST /api/v1/machines/bulk/tags/{add,remove}`).
Client-submitted ids outside the account's scope are silently dropped.

## Power actions

Reboot and shutdown (`action.power`) are fire-and-forget (the connection
may drop mid-command — expected), have no run history (reachability shows
the machine going down and back), need a dedicated confirmation page with
the machine's typed name (`ALL MACHINES` for the fleet), and skip machines
without a pinned host key.

## Supported distributions

Debian and its derivatives, plus Proxmox VE/Backup Server/Mail Gateway,
for as long as each is supported upstream. Commands use stock or standard
optional tooling; missing tools degrade to "unknown", never an error.

## 🖥️ Interactive SSH terminal

**Terminal** opens a real shell in the browser — the most powerful
capability in the app:

- its own permission, `action.terminal`, and a pinned host key;
- start and end are audited (`machine.terminal.open` / `.close` with
  duration), keystrokes and output are not;
- a WebSocket authenticated by hand (session cookie, permission, scope,
  same-origin check) before `accept()`; hard 2-hour cap;
- AsyncSSH PTY with raw bytes; binary frames for terminal data, JSON text
  frames for `resize` / `error`;
- **xterm.js 6, vendored** (`@xterm/xterm` 6.0.0, `addon-fit` 0.11.0,
  `addon-webgl` 0.19.0). The WebGL renderer keeps ANSI colors working
  under `style-src 'self'` (xterm's DOM renderer injects `<style>`, which
  CSP blocks); if WebGL is unavailable, `xterm-csp.css` supplies those
  rules (only 24-bit color is lost). To upgrade, replace the vendored files
  from the npm tarballs and check the terminal in a real browser for CSP
  errors.
- Not in the REST API.

## 🕒 Scheduling

**Scheduling** runs an existing action — system update, update check,
facts refresh, monitoring sample, reboot, shutdown, run command — against
a machine, a group or all machines on a cron expression.

- Actions come from a registry (`register_action()`) wrapping the same
  `machine_actions` functions the buttons use, so a scheduled run and a
  click behave identically.
- A Beat tick every minute runs due tasks with one indexed query on
  `next_run_at`, advanced before the action runs.
- **Time zone per task** (IANA name, default the instance `TZ`); tasks
  from before 0.78.0 stay on UTC. The form previews the next 5 runs
  (`GET /api/v1/scheduling/cron-preview?expression=…&timezone=…`).
- **Unattended updates**: *reboot afterwards only if needed* (waits up to
  15 min for SSH to return) and *one machine at a time* (stops at the
  first failure).
- **Maintenance windows**: a task can be limited to machines inside an
  active window, and a window can pause scheduled tasks.
- Reboot/shutdown are schedulable and not re-confirmed when they fire
  (marked ⚠ on the form). No per-run history beyond `last_run_summary` —
  each action keeps its own record.
- A restricted account can't target "All machines" and can only schedule
  within its scope.
