# 🖥️ Machine Management

*Everything about a managed machine once it's added: SSH host key pinning,
secrets, updates (run/preview/rollback/check), facts/packages/services,
monitoring, logs, live updates, readiness, tags, saved views, bulk
actions, power, the interactive terminal, and scheduling. Split out of
[Architecture](Architecture.md) so this one topic is easier to search —
start there for the rest (auth/RBAC, audit log, notifications, HTTP
hardening).*

### 🔑 SSH host key pinning

Covered in depth in
[SSH Host Key Verification](SSH-Host-Key-Verification.md). Summary: no
connection is ever made to a machine whose host key fingerprint hasn't
been explicitly confirmed by a human, and any later mismatch hard-fails
the connection instead of silently reconnecting.

### Machine/group configuration export & import: structural, not a credentials backup

`app.services.machine_config` (used by both `app/web/routes/machines.py`
and `app/web/routes/api_v1.py`) exports every machine's and group's
*structural* configuration for re-import elsewhere. It never touches
`Machine.secret_encrypted` or `Machine.host_key_fingerprint`:

- A `ssh_key`-auth machine imports cleanly.
- A `password`-auth machine can't be re-created with that method (there's
  no secret to import); it comes back as `ssh_key`, and its name is
  surfaced in the result so an operator knows to revisit its credentials.
- Every imported machine starts with no pinned host key — the normal
  "Discover key fingerprint" + outside-the-app confirmation flow applies
  before anything connects to it.

Conflict handling: an existing machine name is **skipped**, not
overwritten; an existing group name is **reused** for membership. Import
creates directly into `Machine`/`MachineGroup` — unlike CSV bulk-import
(`POST /machines/import`) and self-registration, which land in the
`PendingMachine` review queue because those inputs describe genuinely
unknown hosts.

The same config-as-code convenience — JSON export/import, one service
function behind both web+API — extends to two more resources:

- **Roles** (`app.services.role_config`): lossless round-trip of every
  `Role` and its exact permissions — no credentials involved. Existing
  name **skipped**; an unrecognized permission (a newer-version export)
  is dropped and called out, not a failed import.
- **Scheduling** (`app.services.scheduling_config`): every
  `ScheduledTask`, target resolved to a **name**, portable across
  deployments. Import re-resolves it and **skips** the task (never
  partially) if the name or action isn't found here. Task names aren't
  unique, so always create-only — re-importing twice creates two
  schedules. Every task also checked against the importer's own
  machine-group scope and any `extra_permission` the action needs — same
  as the manual "New scheduled task" form, so import can't plant
  something outside what that account could create by hand.

### Secrets at rest

Machine passwords, the app's own SSH private key, TOTP secrets, and every
third-party API key stored for the [AI assistant](AI-Assistant.md) or
LDAP/OIDC login are encrypted in Postgres with **AES-256-GCM**
(`app.core.security`) — a fresh random nonce per value, keyed by the full
32 raw bytes behind `ENCRYPTION_KEY`. The encryption key lives only in
that environment variable — never in the database or the repo. This does
**not** replace user authentication; it protects these secrets from a
database-only compromise (a leaked backup, a misconfigured read replica).
See "FIPS alignment" below for why AES-256-GCM specifically, and for what
happens to a value still stored in the older Fernet/AES-128 format.

### FIPS alignment

debcontrol does not claim FIPS 140-2/140-3 **certification** — that means
running against a NIST-validated cryptographic module (a CMVP
certificate), which is a build/deployment decision (which OpenSSL build,
which base image) no amount of application code can grant on its own. The
stock `python:3.14-slim` base image, the `cryptography` package's own
vendored (Rust-built) OpenSSL, and Caddy's Go `crypto/tls` are all
**not** FIPS-validated modules as shipped.

What the app *can* control — and does — is never relying on an algorithm
FIPS wouldn't approve, so a deployment needing real certification only
swaps the underlying crypto module (RHEL UBI + validated OpenSSL, or a
FIPS-mode load balancer in front of Caddy), nothing here:

- **Secrets at rest**: AES-256-GCM, not Fernet's AES-128 — both
  FIPS-approved, this is "prefer the stronger modern default," not a
  fixed weakness. `decrypt_secret` still reads the legacy Fernet format
  transparently; `scripts/reencrypt_secrets.py` upgrades the rest in one optional pass.
- **Signed tickets** (pending-TOTP, WebAuthn challenge) — explicit
  `digest_method=hashlib.sha256` over `itsdangerous`'s own HMAC-SHA1
  default. HMAC-SHA1 is itself still FIPS-approved for a MAC — again not
  a fix, just one non-approved-*looking* default removed.
- **Session tokens and the SSH host-key fingerprint** already used
  SHA-256 from the start — nothing to change.
- **SSH connections to managed machines** restrict key exchange/
  encryption/MAC to an approved subset — NIST-curve ECDH (P-256/384/521)
  or ≥2048-bit DH with SHA-2, AES-GCM/AES-CTR, HMAC-SHA-2 — excluding
  AsyncSSH's broader defaults (curve25519/448, chacha20-poly1305, legacy
  ciphers, SHA-1/MD5 MACs). **Not** applied to host-key discovery (must
  stay unrestricted to learn whatever type a machine has) or the
  accepted host-key algorithm (this app pins by exact fingerprint, not
  algorithm — narrowing it could lock out a machine already pinned on an
  Ed25519 key).
- **TOTP** (HMAC-SHA1 per RFC 6238) and **WebAuthn/passkeys**
  (ECDSA P-256/RSA) already only use approved algorithms.

**The one deliberate exception: Argon2id for password hashing.**
FIPS/SP 800-132 only approves PBKDF2 — Argon2id isn't on the list at
all. Kept anyway: memory-hard, meaningfully more GPU/ASIC-resistant than
PBKDF2, exactly what protects an account if the password hash table ever
leaks. Swapping it would trade a real security property for a checkbox —
a considered trade-off, not an oversight: stronger than FIPS where that's
a genuine improvement, not the letter of the standard at a real cost.

### One shared SSH identity, not one key per machine

debcontrol generates a single ed25519 keypair on first use and reuses it
everywhere "SSH key" is the chosen auth method. The private half never
touches disk in plaintext — decrypted in memory only for a connection's
duration. Public half shown on **Settings**; appending it to
`~/.ssh/authorized_keys` is a manual step. Per-machine passwords remain
a fallback, marked not-recommended in the UI.

Rotation ("Generate replacement key") generates a *second* keypair into
`pending_*` columns rather than replacing the active one — switching
immediately would lock the app out of everything at once. The pending
key needs to reach every machine's `authorized_keys` first, by hand or
via **"Push pending key to all machines"**: connects to every
`AuthMethod.SSH_KEY` machine with a pinned host key using its *current*
credential, appends the pending key, idempotently. Password-auth
machines untouched. Once every machine has the new line, "Activate" swaps it in
(`activate_pending_identity`). Before activating, a pending key can also be
thrown away with **"Discard pending key"** (`discard_pending_identity`) —
useful if the push didn't reach every machine and you'd rather start over
than half-activate.

### Self-registration is not the same as trust

`POST /api/inform` lets a machine announce itself (IP, hostname, basic
facts it can read locally) using a shared bearer token (`INFORM_TOKEN`) —
meant for a first-boot/cloud-init script, see
[Machine Requirements](Machine-Requirements.md). It only
ever creates a `PendingMachine` row for a human to look at; it grants no
access and establishes no trust. Turning a pending entry into a real
`Machine` still goes through the ordinary add-machine form and the
mandatory host-key discovery/confirmation flow.

`ansible/debcontrol-onboard.yml` automates everything a machine needs
*before* that POST — the account, its SSH key, the scoped sudoers files —
then makes the same call. It's a single flat playbook meant to be copied
into or `import_playbook`'d from an existing provisioning pipeline. No
secret has a default baked in (public key, URL, and bearer token are all
required vars) — see [Ansible Onboarding](Ansible-Onboarding.md).

### System updates

`apt-get update` / `dist-upgrade` or `full-upgrade` / `autoremove` /
`autoclean` (**Machines → a machine → System updates**, or scoped to a
group / "All machines") needs root on the target and can run long:

- **A dedicated long timeout** — `AppSettings.update_timeout_seconds`
  (Settings → Checks & retention; default 30 min), read fresh on every
  run, distinct from the 60s default every other job uses. Celery's own
  hard per-task kill switch is a separate, generous, fixed constant
  (`app.tasks.jobs._UPDATE_TASK_TIME_LIMIT_SECONDS`) sized to comfortably
  exceed the maximum this setting can be configured to — not itself
  configurable, since a Celery task decorator argument can't read the
  database.
- **Cleanup always runs, chained by `;` not `&&`** — a failed upgrade
  still runs `autoremove`/`autoclean`; the upgrade step's own exit
  status decides succeeded/failed.
- **`sudo -n` throughout**, never bare `apt-get` — non-interactive, so
  missing passwordless sudo fails fast and clearly instead of hanging on a password prompt.
- **Every run is a row** — `MachineUpdateRun` persists status/output/
  error/timestamps in Postgres (Celery's own result backend has a TTL).
  `batch_id` (a shared UUID, not an FK) links one group/"All machines" trigger's runs.
- **Fan out, don't await** — a group/"all" trigger creates every row and
  enqueues every job in one commit, then returns.
- **Full history** — the Updates tab shows the trigger form and full
  paginated, filterable run history together, same pagination convention as `/audit`.
- **Live output** — `run_system_update` reads stdout incrementally
  instead of buffering it all, writing to the run row every ~2s — what
  makes the page's own 3s poll show progress instead of a static spinner.

### Previewing a manual update before it runs

"Run update" links to a preview first — simulates the *exact* command
sequence via apt's dry-run (`apt-get -s`), shows what would be
installed/upgraded/*removed*. Only the preview's "Confirm" button
triggers the real thing (same permission, fingerprint check, audit code).

- **Scoped to this one entry point** — scheduled and group/bulk updates unchanged.
- **A plain confirm button, not typed-name** — removals called out prominently as a warning.
- **A GET, not a POST** — persists nothing, no CSRF needed.
- **An empty plan still lets you confirm** — clicking still runs the full sequence.
- **The API keeps a direct trigger** — the preview is offered alongside, not forced.
- **Reuses `check_updates`'s parsing conventions** — same marker-delimited
  sections, `parse_apt_simulated_changes` a pure sibling of
  `parse_apt_upgradable_packages`.

### Rolling back an update

Every real update run captures a "before" picture (`dpkg-query -W`)
right before the upgrade step, stored as
`MachineUpdateRun.package_snapshot`. A capture failure is logged and
never fails the update run itself — it just means rollback isn't
offered for that run, same as any run from before this feature existed.

`POST /machines/{id}/updates/{run_id}/rollback` (same `action.updates`
permission — undoing isn't higher trust) creates a **new**
`MachineUpdateRun` with `rollback_of_run_id` pointing at the source, then:

1. Captures a **fresh** snapshot — not a blind replay of the old one.
2. Diffs it against the stored snapshot, keeping only packages that
   actually changed since. Something touched by an unrelated run/manual
   `apt` command is left alone — this only ever undoes what *this* run
   changed, and re-running it is a fast no-op the second time.
3. If anything's left, re-installs those exact `package=version` specs
   via `--allow-downgrades` — needs the old `.deb` still resolvable from
   a configured apt source, or apt fails with its own clear error.

A first-class row in the same history (a "rollback" badge), not an edit
to the original. A rollback of a rollback is refused (`400`) — roll back
to a specific earlier state by rolling back *that* run directly. The API
mirrors the web route.

### Checking for updates without installing them

"Check for updates now" needs root for the apt cache refresh
(`apt-get update`); the enumeration after it (`apt list --upgradable`)
doesn't. Shares `run_system_update`'s long timeout; its periodic sweep
runs on the same cadence as facts refresh. A failed check (usually: sudo
not configured yet) resets counts to "unknown" rather than a stale number.

Reboot-required needs no privileges (`uname -r` vs. the newest installed
`linux-image-*` via `dpkg`), so it rides along in the facts command.

### Which packages, not just how many

`check_updates` returns both counts and the actual list — name, current
version, new version — as `PendingPackage`, stored as a JSON column per
source on `Machine`, same pattern as `disks`. No history table: "what a
check most recently found," overwritten on every
run. A manual click, the periodic sweep, and a **user-created scheduled
task** using the `check_updates` action all write the same columns.
apt's entry gets a real version diff (`apt list --upgradable`'s
`[upgradable from: X]` suffix, parsed with a regex); flatpak/snap only
surface the available version.

### Facts gathered

All in one `FACTS_COMMAND` round trip (`app/ssh/facts.py`), using the same
`echo ===MARKER===`-per-section convention — no extra SSH connection, no
privilege requirement, and chosen for portability over a minimal image.
Besides the periodic sweep (`FACTS_REFRESH_INTERVAL_SECONDS`), Overview's
**Refresh now** button (`POST /machines/{id}/refresh-facts`, `machine.manage`)
runs the same job synchronously and waits for the result inline
(`asyncio.to_thread(async_result.get, timeout=...)`) instead of returning
immediately and relying on the next poll — the packages and services
snapshots below each have their own equivalent button:

- **CPU architecture**: `uname -m`.
- **CPU model**: `lscpu`'s own `Model name:` line, tolerant of the
  leading whitespace modern `util-linux` nests it under in its tree-style
  output. Falls back to `/proc/cpuinfo`'s `model name` field only if
  `lscpu` itself is missing — that field alone is x86-only and reads back
  empty on any ARM machine (a Raspberry Pi, an ARM cloud instance), which
  `lscpu` doesn't have that gap on.
- **Uptime**: `/proc/uptime`'s first field via `awk`, floored to whole
  seconds — no `uptime`/`procps` binary needed.
- **Process count**: `ls -d /proc/[0-9]*/ | wc -l` rather than
  `ps -e | wc -l`, since `procps` isn't in Debian's minimal base system.
- **Filesystem usage**: `df -B1 --output=target,size,used,avail,pcent`,
  excluding `tmpfs`/`devtmpfs`/`squashfs`/`overlay`; `-B1` forces byte
  units. Parsed by taking the *last four* whitespace-separated fields as
  size/used/avail/pcent and joining everything before that as the mount
  point — a mount point containing a space is an accepted, documented edge
  case that breaks this.
- **Network interfaces**: `ip -4 -o addr show scope global`, filtered to
  global-scope (not loopback/link-local) IPv4 addresses. `iproute2` is
  standard on any non-minimal Debian/Ubuntu install; missing entirely just
  yields an empty list, same graceful degradation as every other fact.
- **Physical vs. virtual** (`Machine.is_physical`): `systemd-detect-virt`
  — prints `none` and exits non-zero on bare metal, or the hypervisor name
  and exits 0 inside a VM/container. `None` (unknown) if the binary itself
  is missing. Gates the hardware-monitoring probe below — self-healing on
  every facts refresh, so a machine physically migrated between bare metal
  and a VM (or vice versa) picks up the right behavior on its own next
  sweep, no manual toggle.

### flatpak and snap: optional, guarded, never blocking apt

Updates and the availability check cover apt, flatpak, and snap, but
neither flatpak nor snap is assumed installed — every step is wrapped in
`command -v`, so a machine without one just skips that part, never a failure.

The check-side commands are genuine, side-effect-free dry runs:
**flatpak** has no `--dry-run` for `update`, so `flatpak remote-ls
--updates <remote>` is the read-only equivalent, de-duplicated by app id
(an app tracked from two remotes shouldn't double-count); **snap**:
`snap refresh --list`, snapd's own dry-run listing, no root needed.

Applying updates is different: `flatpak update`/`snap refresh` both run
via `sudo -n` like apt — opt-in (the sudoers example marks those two
lines optional), and without them only those two steps fail (visible in
output); apt is unaffected since the three are `;`-chained.

Counts from all three appear everywhere apt's already did — machine
list, detail page, dashboard tally, REST API — as separate fields
(`flatpak_upgradable_count`, `snap_upgradable_count`), not merged into
`upgradable_count` (which also carries a `security_upgradable_count`
breakdown neither has an equivalent for).

### Installed packages: a snapshot table, not a JSON blob

**Installed packages** stores a `MachinePackage` row per package (not a
JSON column, the pattern `disks` uses), so the list is filterable/
countable with an ordinary SQL query.

One SSH round trip for `dpkg-query`, then flatpak/snap if present — none
need root. A refresh replaces the whole set in one transaction
(delete-then-bulk-insert) — a snapshot, not a history. Same cadence as
facts, plus one extra trigger: a finished update run enqueues both a
package refresh and a fresh update-availability check regardless of outcome.

`held` (`apt-mark showhold`) is a per-row boolean, not a separate list. flatpak/snap always `held=False`.

### Systemd service snapshot

`MachineService`, one row per `systemctl list-units --type=service --all`
unit, same snapshot/replace pattern and cadence as packages — a full unit
listing doesn't need to be fresher than facts. No root needed — listing
unit state is allowed under systemd's default polkit policy. Shown as the
**systemd services** table at the bottom of the Monitoring tab (filter
box, sortable columns), and at `GET /api/v1/machines/{id}/services`.

Each *running* unit also carries its own cgroup accounting, read in the
same round trip with `systemctl show -p Id,CPUUsageNSec,MemoryCurrent,
MemoryPeak,ActiveEnterTimestampMonotonic` (`app/ssh/services.py`):

- **CPU (avg)** — the unit's CPU-time delta since the *previous* snapshot
  divided by the wall-clock time between the two, as a share of the whole
  machine (all cores = 100%) — so on the default cadence, a 10-minute
  average. Computed in `app.tasks.jobs._service_usage` from the previous
  row before the snapshot is replaced; only when both rows belong to the
  same run of the unit (`ActiveEnterTimestampMonotonic` unchanged —
  otherwise the counter reset with the restart).
- **Peak CPU** — the highest of those averages since the unit last
  started.
- **Memory** / **Peak memory** — `MemoryCurrent`, and systemd's own
  `MemoryPeak` (systemd 255+), falling back to the highest `MemoryCurrent`
  seen since the unit last started on older systemd.

Not running, or accounting off → `N/A`, not zero. The Monitoring tab's
**Refresh now** refreshes this snapshot too.

### Monitoring tab layout

A two-column grid of chart cards (one column below ~1000px), modeled on
Beszel's system page, then full-width tables:

- **CPU usage**, **Memory usage**, **Disk usage** (per mount), **Disk I/O**
  and **Network** (read/write and received/sent as separate series per
  device/interface), **Load average**, **Availability** and **Connect
  latency** (the reachability history — see below).
- **Docker** (any machine with a `docker` CLI): stacked per-container
  **CPU**, **memory** and **network** charts plus an **All containers**
  table (CPU, memory, network rate, health, ports, image, status).
- **Hardware** (bare metal only — see below): **Temperature**, **Fans**,
  **CPU power**, **GPU power**, and per GPU a **utilization** and **VRAM**
  chart named after the card.
- **S.M.A.R.T.** table (bare metal): device, model, capacity, status,
  type, power-on time, power cycles, temperature — clicking a device opens
  a side panel with every attribute smartctl reported.
- **systemd services** table (above).

Charts are drawn server-side by `app/web/charts.py` (smooth monotone
curves, filled or stacked areas, round-number Y ticks, evenly spaced time
labels) into a stretched, text-free SVG; axis labels are HTML laid out by
flexbox, so nothing needs an inline style under the CSP.
`static/js/monitoring-chart.js` adds the hover tooltip (every visible
series at that point, highest first — built with `textContent`, since
sensor/container names come from the managed machine), legend toggling,
the per-card series filter, and the tables' filter/sort. A configured
condition-based notification's threshold is drawn as a dashed line on the
chart it's about, with its value in the legend.

### Docker containers

`MONITORING_COMMAND` ends with a `DOCKER` section on every machine that
has a `docker` CLI (VMs included — this isn't hardware): plain `docker`
first (the account is in the `docker` group), else `sudo -n docker` when a
sudoers rule allows exactly that binary (`sudo -n -l <path>` checks
without prompting). Neither → `Machine.docker_status = "no_access"` and
the tab explains how to grant it. Onboarding grants it when Docker is
installed at onboarding time: a separate `/etc/sudoers.d/debcontrol-docker`
for whatever path that machine's `docker` resolves to (same pattern as the
flatpak/snap file). That's root-equivalent — anyone who can start a
container can mount the host filesystem — but no more than the `apt-get`
grant the account already has. A machine onboarded before this, or that
got Docker afterwards, picks it up by re-running onboarding. `docker ps -a` gives the table; `docker stats
--no-stream` the CPU/memory; network bytes come from each container's own
namespace (`/proc/<pid>/net/dev`, exact counters) and only fall back to
`docker stats`' rounded NetIO when that file isn't readable.
Host-network containers are skipped there (their namespace is the host's).

**Container actions.** With `action.power` (the same permission as
reboot/shutdown — stopping a service's container is the same kind of
disruptive action), each row of the container table has **Restart** and
**Stop** (running containers) or **Start** (stopped ones), each behind a
confirmation dialog. `POST /machines/{id}/containers/{name}/{action}`
(`app/ssh/containers.py`) validates the name against Docker's naming rule
and the action against `start`/`stop`/`restart` before anything reaches
the machine, runs it through the same Docker access probe, waits for
docker's answer (its own exit status, echoed back — not the SSH channel's),
audit-logs `machine.container.<action>`, enqueues a fresh monitoring sample
so the table catches up, and redirects back with the outcome. REST:
`POST /api/v1/machines/{id}/containers/{name}/{action}`.

**Image updates.** Once a day (04:30, `check_all_machine_image_updates`,
one task per machine where Docker is readable) and on demand (*Check
image updates* on the container table, `machine.manage`, or
`POST /api/v1/machines/{id}/docker/check-images`),
`app/ssh/image_updates.py` compares each running image's local repo
digest(s) with the registry's current digest for the same tag, read via
`docker buildx imagetools inspect` — manifest only, nothing is pulled.
A differing digest marks the image **update available** in the table
(`Machine.docker_image_updates`), and `docker.image_updates_count` can
drive a notification. Digest-pinned references, locally built images, and
registries this machine can't reach are "unknown". It's detection only —
updating is still `docker compose pull && up -d` (or your own tooling);
one registry request per distinct image per day keeps it well inside
Docker Hub's anonymous rate limit.

The latest full container list is kept once on `Machine.docker_containers`;
each sample stores only the numbers the charts need
(`MachineMonitoringSample.docker_stats`), so image names and port lists
aren't repeated every two minutes.

### Endpoint checks (TLS certificates, HTTP)

**Checks** (`/checks`; `machine.view` to see, `machine.manage` to add,
edit, delete or *Run now*) are independent of machines — they run from the
debcontrol server's Celery worker, so they test reachability *from
outside*, the way users see a service:

- **HTTP** — a GET against a full URL, redirects followed; up when the
  status equals the configured one (or is below 400 when none is set). An
  https URL also reports its certificate's expiry.
- **TLS** — a handshake with `host[:port]` (443 by default), certificate
  expiry only. With *Verify* on (the default), an invalid chain/hostname
  counts as down; the expiry date is still read (a second, unverified
  handshake), so an expired certificate says *when* it expired.

`run_due_endpoint_checks` (Beat, every minute) enqueues each enabled check
whose own interval (30 s–1 day) has passed. Only the latest result is
stored (`EndpointCheck.last_*`, `cert_expires_at`). Notifications: an
outage is announced after **2 consecutive failures** (`endpoint.down`),
recovery only after an announced outage (`endpoint.recovered`), and a
certificate inside its warn window once per certificate
(`endpoint.cert_expiring`) — see `app/services/endpoint_checks.py`'s
`apply_result`. Targets are fetched by the server, so only
`machine.manage` accounts can add them (the same trust level as a
notification webhook URL). REST: `GET/POST /api/v1/checks`,
`PUT/DELETE /api/v1/checks/{id}`, `POST /api/v1/checks/{id}/run`.

### Fleet page

`/fleet` (nav: **Fleet**, `machine.view`) shows every visible, active
machine as a compact card — status dot, CPU, RAM, the fullest filesystem,
the hottest sensor (bare metal), load/cores, uptime, running/total
containers and a "disk full in ~N days" flag when the forecast is under
30 days. The card's top border takes the worst reading's color (warn at
75 %, danger at 90 %; temperatures at 70/85 °C; offline or an
unhealthy/restarting container is always danger), and a summary strip
counts online/offline/needing attention. Built by
`app/services/fleet_overview.py` from each machine's latest monitoring
sample — one batched window query for the whole page, the same one the
Machines list's Cards view uses — plus columns already on `Machine`. The
grid re-fetches itself every 60 s (htmx `hx-select` against the same
page); the name filter is client-side. Capped at 500 machines (the
paginated Machines list covers larger fleets). REST: `GET /api/v1/fleet`.

### Disk-full forecast

Every hour (`forecast_all_machine_disks`, one job per machine, database
only, no SSH), `app/services/disk_forecast.py` fits a least-squares line
through each mount's used bytes over the last 7 days of monitoring
samples and extrapolates it to the mount's size. The result lives on
`Machine.disk_forecast` (`{mount: {bytes_per_day, days_until_full, ...}}`),
shown on the Monitoring tab's Disk usage card ("full in ~23 days,
+1.2 GB/day"), exposed on `GET /api/v1/machines/{id}/hardware`, and usable
as the `monitoring.disk_full_days` notification condition (the soonest
mount). It needs at least 6 samples spanning 6 hours; a mount that isn't
growing (or wouldn't fill within ~10 years) has no estimate. It's a
trend, not a promise — a cleanup or log rotation changes the slope and
the next hourly run picks that up.

### Hardware monitoring: physical machines only, self-healing

The hardware cards appear only when `Machine.is_physical` is true (see
Facts gathered, above) — a VM's `sensors`/S.M.A.R.T./RAPL/GPU readings
would be either absent or actively misleading (a virtual disk has no real
S.M.A.R.T. attributes), so the probe is skipped entirely rather than shown
empty.

When `is_physical`, the same monitoring SSH round trip appends a second
`_HARDWARE_COMMAND` (`app/ssh/monitoring.py`):

- **Temperature sensors** and **fan speeds**: `sensors -j` (lm-sensors),
  parsed from its own JSON — each chip → feature → `*_input` reading,
  bucketed into temps vs. fans by whether the feature name starts with
  `temp`/`fan`, and named `<driver> <feature>` (`k10temp Tctl`, `nvme
  Composite`) so identical feature names on different chips stay
  distinct (a second identical name gets a ` (2)` suffix). Missing
  `sensors` or malformed JSON degrade to an empty list, never an error.
- **S.M.A.R.T. health**: `smartctl -H` per whole disk, the PASSED/FAILED
  bit kept per sample. The full detail (model, serial, capacity, hours,
  cycles, temperature, every attribute) is gathered with *facts* instead —
  see below. Needs root: the onboarding sudoers line includes
  `/usr/sbin/smartctl` for newly onboarded machines; an already-onboarded
  one gets it after re-onboarding (until then: `unknown`, not a crash).
- **CPU power** (Intel and AMD): RAPL's
  `/sys/class/powercap/*-rapl:*/energy_uj` (`intel-rapl:*` and
  `amd-rapl:*`, AMD Zen 2+ on kernel 5.8+), summed over the `package-*`
  domains (sub-domains are already part of a package's total). A
  cumulative microjoule counter, world-readable; stored raw per sample
  (`cpu_energy_uj`) and turned into watts from consecutive samples, the
  same downstream-rate pattern network/disk I/O use. A CPU with neither
  RAPL variant reports nothing.
- **GPUs** (NVIDIA, AMD, Intel), one entry per card
  (`MachineMonitoringSample.gpus`): NVIDIA via `nvidia-smi` (utilization,
  VRAM used/total, power); AMD/Intel via the DRM driver's sysfs —
  `gpu_busy_percent` and `mem_info_vram_*` (amdgpu; i915/xe don't expose
  these) and the hwmon `power1_average`/`power1_input` reading when the
  driver registers one. The card's name comes from its `product_name`
  file, else `lspci -mm` for its PCI slot (the bracketed marketing name,
  vendor-prefixed — "AMD Radeon RX 550"), else the card id. Emulated
  adapters (QEMU, VMware) and cards reporting no metric at all are skipped.
  `gpu_power_watts` is the sum across cards, falling back to an
  `amdgpu`/`i915`/`xe` chip's power reading in the `sensors -j` dump.

Every one of these self-heals: sensors, fans, disks or GPUs appearing or
disappearing between sweeps is reflected on the next sample with no
reconciliation step, since each sample stores its own full snapshot. On
the charts, a series simply starts (or stops) where the device did.

### S.M.A.R.T. detail (facts cadence)

`FACTS_COMMAND` ends with a `SMART` section (`app/ssh/smart.py`): on bare
metal only (checked in-shell with `systemd-detect-virt`) and only when
`smartctl` exists, one `smartctl -a -j` per whole disk, stored as
`Machine.smart_devices` — a snapshot replaced on every facts refresh
(10 minutes by default), since none of it moves on a minutes scale and
the full dump is far bigger than the health bit the 2-minute sample keeps.
`sudo -n -l` checks for the sudoers grant *before* running, so smartctl
runs once per disk — its exit status is a bitmask that's non-zero even on
a readable disk with logged errors, so `sudo ... || plain ...` would have
run it twice. ATA disks keep the classic id/value/worst/threshold/raw
table (a currently-failing attribute is flagged); NVMe disks their flat
health-log fields. Also at `GET /api/v1/machines/{id}/hardware`, with the
Docker list and the latest sensor/GPU readings.

Unlike every table earlier, `MachineMonitoringSample` genuinely is a
history: one row appended per `MONITORING_INTERVAL_SECONDS` tick, purged
against `monitoring_history_retention_days` (or a per-machine override).
Each sample carries CPU/load/RAM, cumulative interface/device counters
(diffed into a rate by `app/services/monitoring_history.py`), and
filesystem usage (same shape the facts snapshot uses, just historized on
this table's shorter cadence — a small addition to an existing round
trip, not a new connection). Graphs downsample raw rows to a target
point count in Python — positional bucket-averaging, since neither
Postgres nor the SQLite test backend has a time-series extension —
rendered as an interactive, dependency-free inline SVG
(`trend_chart`): hover/drag scrubs a cursor showing the exact value and
timestamp, unlike the Dashboard's plain, non-interactive sparklines.

### Availability: historized from the existing reachability sweep, not ICMP

The per-minute reachability sweep already updated `Machine.is_reachable`/
`last_ping_at` every tick; it now *also* appends a
`MachineReachabilitySample` — the exact same check, just kept instead of
only overwriting those two columns. No new connection, no new probe,
still a plain TCP connect to the SSH port rather than ICMP (a host that
blocks ICMP but serves SSH should still read as reachable, and vice versa).

A genuinely separate table from `MachineMonitoringSample`, not a column
on it — different failure semantics: a reachability sample is written
whether the check succeeded *or failed* (the whole point is capturing an
outage), while a monitoring sample is never even attempted when SSH
can't connect. Shares the monitoring retention setting rather than
getting its own — one "how long does history stick around" knob, not
two. `build_availability_history` turns raw samples into an
uptime-percent series (average of 100/0 per check) and a latency series
(successful checks only — a failed check has no connect time to average).

### Logs: no storage, gated behind `action.terminal`

**Logs** is a live SSH round trip on every view, from one of three
sources picked at the top of the tab: the **system journal**
(`journalctl`, the default), **one file** under a configurable path
allowlist (typed, or picked with *Browse*), or **one Docker container**
(`docker logs --timestamps`, stdout and stderr merged). Nothing stored:
only that a view happened is audit-logged, never the content. Gated behind
`action.terminal`, not the plain `machine.view` every read-only tab
above uses — reading logs is a materially different trust level than a
fact, even without root, and an admin who can already open the terminal
could read any of it directly anyway.

The Docker picker lists the containers from the latest monitoring sample
(`Machine.docker_containers`, see *Docker containers* above) — no extra
round trip just to fill a dropdown — and defaults to the first running
one. The chosen name is validated against Docker's own naming rule
(`[a-zA-Z0-9][a-zA-Z0-9_.-]*`) before it's ever sent, then shell-quoted
like every other argument; Docker access uses the same `docker` group /
`sudo -n docker` probe as monitoring. Searching filters the *whole* log
(`grep -F`) and keeps the last N matches, like the file mode. Also on the
REST API: `GET /api/v1/machines/{id}/logs?container=<name>`.

The viewer numbers lines, colors ones that look like errors/warnings
(`app/web/log_lines.py` — a word-boundary match on error/fail/fatal/…,
warn/deprecated), highlights the search term exactly as the machine-side
filter matched it, and starts scrolled to the newest line; *Wrap lines*
and *Jump to end* are `static/js/log-viewer.js`. Log content is plain
autoescaped text throughout — it comes from the managed machine.

**Follow live** streams new lines as they're written, over a WebSocket
(`app/web/routes/logs_ws.py`, `/machines/{id}/logs/follow/ws`) rather than
a page refresh: `journalctl -f`, `tail -F` (keeps following across log
rotation) or `docker logs -f`, each starting from the last 50 lines and
filtered by the same search term (`grep --line-buffered` so matches arrive
immediately) — built by `app.ssh.logs.build_follow_command` with the same
path allowlist and container-name validation as the one-shot view. The
socket authenticates exactly like the terminal's (session cookie,
`action.terminal`, machine scope, pinned host key — all before `accept()`),
is capped at one hour, and tears down the SSH process on disconnect. Start
and stop are audit-logged (`machine.logs.follow` / `.follow_end`, with the
duration), never the content. The browser builds each streamed line with
text nodes only, applies the same error/warn coloring, keeps the newest
5 000 lines, and only auto-scrolls while you're already at the bottom.
Web-only, like the terminal: a never-ending stream has no useful REST shape
(`GET /api/v1/machines/{id}/logs` covers the snapshot).

### Live updates: a WebSocket doorbell, not a data feed

The Overview, Monitoring, and Updates tabs' status/facts/packages/
services/update-availability panels used to be pure htmx polling —
`hx-trigger="every 20s"` (or 30s), meaning up to that long a wait after a
background job finished before an open tab showed it. Each of those panels
now also carries `live-<kind> from:body` in its `hx-trigger` (e.g.
`live-facts from:body`), and the polling interval itself was stretched to
60s, now just a fallback for a missed push:

- **`app/services/live_updates.py`** — `publish_machine_event(machine_id,
  kind)` publishes `{"kind": "..."}` to a per-machine Redis pub/sub channel
  (`debcontrol:live:machine:<id>`). Called from `app/tasks/jobs.py` right
  after the commit that makes a change visible — reachability sweeps
  (`status`), facts/package/service refreshes (`facts`/`packages`/
  `services`), and update-availability checks (`updates`). Best-effort:
  a publish failure is logged and swallowed, never allowed to fail the job
  itself — a missed push just means that panel's fallback poll catches up
  a little later.
- **`app/web/routes/live_ws.py`** — `GET /machines/{id}/live/ws` (WebSocket),
  one per machine, subscribes to that machine's channel and relays every
  message to the browser verbatim. Pure relay: no DB or SSH access happens
  in this handler at all, so a slow/unreachable machine can never block it.
  Auth follows the same hand-rolled session-cookie + permission pattern
  `terminal_ws.py` uses (`app.auth.middleware` never runs for WebSocket
  requests) — gated behind `MACHINE_VIEW`, not `MACHINE_MANAGE`, since the
  message it relays is only ever a `kind` string naming which
  already-permission-checked htmx panel to re-fetch, never machine data
  itself.
- **`app/web/static/js/live-updates.js`** — opens that socket on any page
  with a `[data-live-machine-id]` element, and turns each `{"kind": "..."}`
  message into a plain `live-<kind>` event dispatched on `document.body`,
  which is what the panels' `hx-trigger` listens for. Reconnects with
  exponential backoff (capped at 30s) on any drop.

This is deliberately a doorbell, not a data channel: the push carries no
machine data, so there's nothing for a stale/duplicate message to get
wrong, and every actual fetch still goes through the exact same
permission/scope-checked htmx endpoint its poll always used.

**Browser notifications** are a pure client-side layer on the same
`live-<kind>` events, in `live-updates.js` itself, not new server
infrastructure: backgrounded tab + opted-in (a "🔔 Enable notifications"
toggle the script injects) → a received event also becomes a
[Notification API](https://developer.mozilla.org/en-US/docs/Web/API/Notification)
popup, click focuses the tab. Deliberately Notification, not Push — no
service worker, no VAPID keys, no server subscription storage, nothing
that fires once the tab/browser is fully closed. Opt-in kept in
`localStorage` (per-browser), and the machine anchor carries
`data-live-machine-name` so the title needs no extra request.

### Post-onboarding readiness check

**Settings** shows a banner if `app.ssh.readiness`'s probes (ncurses-term;
scoped `sudo -n` for apt/shutdown/dmidecode/flatpak+snap) found something
missing — re-run after host-key confirmation, after "Run initial setup",
on demand, **and periodically** for every pinned machine, same cadence
as facts. That periodic sweep is what catches a requirement *un-set*
after onboarding (`ncurses-term` autoremoved, a sudoers grant hand-edited
away), not just a gap at onboarding time. Lives on Settings, not
Overview — a one-time-per-gap config concern, not day-to-day status.

**A `root` connection never has a sudo grant to miss** — every probe
tries `sudo -n` first, falls back to running directly once `id -u` is 0,
so those four always read `ok` for root. Only `ncurses-term` itself can
be missing, and "Install now" installs it with the credential already on
file — no fresh login, no sudoers file, nothing to escalate.

For a **non-root** machine already on the app's own key (no root
credential left to fix a sudo gap with), the banner shows the exact
sudoers line to add by hand — often the only option, since password SSH
to a privileged account is commonly policy-disabled. A "Fix it" form
still offers to do it: collects a one-time root/sudo login, temporarily
puts the machine back in a never-onboarded shape, reuses
`run_machine_onboarding` unchanged — on failure, restores the previous
auth state itself rather than leaving a real password sitting in
`secret_encrypted` (the success-path revert never runs when the script fails).

### Fleet-wide package search

**Package search** answers "which machines have *this*, and what
version" — one query across `MachinePackage`, no new storage. Capped at
500 rows with a "narrow your search" notice past that.

`MachinePackage.machine` is `viewonly=True` with no `back_populates`
(`Machine` has no `packages` collection, to avoid the eager-loading
cost) so results can show which machine each hit belongs to with no per-row round trip.

### Machine runbook: Markdown notes, rendered server-side

A **Runbook** field (multi-line, up to 20,000 chars) separate from the
short, single-line `description` used in the list/search — meant to run
longer: how to deal with this server, who owns it, escalation contact —
rendered as real HTML on Overview, not plain text.

The `markdown` Jinja filter renders it via
[mistune](https://mistune.lepture.com/), a small pure-Python parser, no
transitive deps. Built with **`escape=True` explicitly**
(`mistune.create_markdown(escape=True)`, not the module-level
`mistune.html` convenience, which defaults `escape=False` — raw HTML
passed through unescaped, the opposite of safe here). A `<script>` in
the source renders as inert text; mistune's default link-safety check
neutralizes `javascript:` links. Admin-authored (`machine.manage` only)
but no reason to trust it with markup injection just because of that.

Included in config export/import and the REST API payload, same as
`description`/`tags` — structural, not a credential. Left out of CSV
specifically: its flat-row shape doesn't suit a multi-paragraph field, and JSON already round-trips it in full.

### Machine tags: cross-cutting, independent of the group tree

A free-form **Tags** field (comma-separated) alongside — not instead of —
the single-group membership: `Machine.group_id` stays a strict
one-group-or-none tree, while `Machine.tags` is a plain many-to-many for
labels that don't fit that tree — `prod`, `web`, `praha-dc1`, whatever
— any number per machine. The machine list, "All machines", and each
group's member list gained a **tag** filter (`?tag=...`), and the REST
API accepts the same.

**The machine list's free-text search also matches a tag name** —
typing a tag into the existing search box finds machines carrying it, no
separate picker needed. The old `<select multiple>` tag picker + AND/OR
dropdown are gone in favor of that field doing double duty, but
everything they drove still works by URL: tag badges still link to an
exact `?tag=name`, saved views still capture `tag`/`tag_mode`, the REST
API is unchanged. "All machines"/group pages keep their own single-tag
`<select>` — a much shorter per-group list where a dropdown still pulls its weight.

The table view's own **Tags** column shows every tag as its own badge,
between Group and Status — tags used to render wrapped under a machine's
name, cramped alongside its OS badge and link.

**The machine list specifically** can filter by *several* tags at once —
`?tag=prod&tag=web&tag_mode=and|or` — shared with the REST API. `or` is
one `.any(Tag.name.in_(...))` clause; `and` is one independent
`.any(Tag.name == ...)` clause **per tag**, chained as separate
`.where()`s (SQLAlchemy ANDs them together) rather than combined — each
needs its own correlated `EXISTS`, since a machine must match each tag
separately, not just carry *some* tag from the set. Saved views capture
`tag`/`tag_mode` the same way they capture `q` (dropping `tag_mode` from
the query string whenever it wouldn't change anything — its own `or`
default, or fewer than two tags to have a mode between — so a plain single-tag
view's link looks exactly like it did before `tag_mode` existed). The
REST API's saved-view creation endpoint accepts `tag` as either a single
string or an array, for backward compatibility with a caller built
against the pre-multi-tag shape.

Bulk tag add/remove for an ad-hoc checkbox selection
(`app.services.machine_tags.add_tags_to_machines`/
`remove_tags_from_machines`) is additive/subtractive, unlike the
create/edit form's `set_machine_tags` (which *replaces* one machine's
whole tag set): adding leaves a machine's other tags untouched and
creates any tag that doesn't exist yet; removing leaves other tags
untouched, is a silent no-op for a machine that never had the tag, and
still deletes a tag left with zero machines afterward, same as
`set_machine_tags`. **REST API only** (`POST /api/v1/machines/bulk/
tags/{add,remove}`) — the machine list's own bulk-actions bar
deliberately doesn't surface this, to keep that row to selection-wide
actions (update/reboot/shutdown) and not blur into per-machine tag
editing, which already has its own place (the create/edit form).

Cards view (see the display-modes note below) shows each visible
machine's *latest* monitoring sample as a small CPU/RAM bar — one batched
window-function query (`_get_latest_monitoring_by_machine`, `row_number()
OVER (PARTITION BY machine_id ...)`) for the whole page of machines, not
one query per machine, and skipped entirely for Table/List. Deliberately
just the latest reading, not a historical sparkline — an actual trend
line would mean fetching a whole time window's samples for up to a page's
worth of machines at once, which doesn't scale the way a single indexed
"give me each machine's newest row" query does; a real trend chart is one
click away on that machine's own Monitoring tab. The bar's fill width
avoids an inline `style` (CSP has no `'unsafe-inline'` for `style-src`) by
picking one of 11 fixed `.usage-bar-fill-N0` CSS classes (rounded to the
nearest 10) instead of setting a percentage directly.

### Machine list display modes: Table / List / Cards

A per-browser cookie (same pattern the light/dark toggle uses), not
per-account — a display-density preference, not worth a DB column or
cross-device sync. List is a dense name+status row; Cards is a grid with
OS logo + CPU/RAM indicator. All three share the same bulk-select checkboxes.

`app.services.machine_tags` is the only place `Tag`/`machine_tags` rows are written:

- **Normalized on the way in** (lowercased, trimmed, capped at 64 chars,
  de-duped) — same "normalize once" choice `User.username` makes, so
  `Tag.name` needs only a plain unique index.
- **Created on first use, deleted once nothing references it** — no
  separate "manage tags" page to keep in sync; renaming is remove-old/add-new.
- **Works at the association-table row level**, not the ORM relationship
  attribute — `Machine.tags` is `lazy="selectin"` for reads, but touching
  an *unloaded* relationship on an `AsyncSession` object raises
  `MissingGreenlet` regardless, so writes go directly through
  `select`/`insert`/`delete`, then `db.refresh(..., attribute_names=["tags"])`.

Included in config export/import — structural like `description`, no special exclusion.

### Saved machine-list views: a personal bookmark, not shared config

"Save this view" (shown once `q`/`tag` is set) names the current filter
for replay later, no retyping. Per-account, not fleet-wide — needs
nothing beyond `machine.view`, and one account never sees or deletes
another's.

`query_string` is never accepted verbatim — `build_query_string` only
encodes the fixed, known parameter set (`q`, `tag`) a client actually
submitted, so a saved view can't capture an arbitrary querystring, and
identical filters always produce the identical stored string. A `UNIQUE
(user_id, name)` constraint is the actual duplicate guard.

Also reachable via the REST API, same self-service convention as the
per-user locale endpoints next to it.

### Bulk actions from the machine list

Checkboxes (update, check-updates, reboot/shutdown) call the exact same
`machine_actions.py` functions the group and "All machines" buttons use
— only the `list[Machine]` source differs. Bulk update reuses the
*group* batch-results page, since `batch_id` only ever meant "triggered together."

Power still needs a typed confirmation phrase; an ad-hoc selection has
no name, so it uses the fixed phrase `SELECTED MACHINES` (mirroring "All
machines"'s `ALL MACHINES`), IDs carried forward as hidden fields.

### Supported distributions

"Debian and its derivatives (e.g. Ubuntu), for as long as each is
supported upstream" — a policy, not a version list. Every command
debcontrol runs is stock or standard optional tooling; nothing branches on distro.

### Power actions: fire-and-forget, double-confirmed, untracked

Reboot and shutdown:

- **No persistent history**, unlike `MachineUpdateRun`. `shutdown -r/-h
  now` returns almost immediately, but the connection can legitimately
  tear down mid-response — expected, not an error. The reachability
  check already shows the machine going offline and back.
- **Confirmed twice**, not stacked JS `confirm()` dialogs — a dedicated
  page, then typing the exact name, checked server-side (not just
  disabled-until-typed in the browser). "All machines" uses `ALL MACHINES`.
- **Same eligibility rule as updates**: silently skips any machine
  without a pinned fingerprint (surfaced as a skipped count).

### 🖥️ Interactive SSH terminal: the most powerful capability in the app

**Terminal** opens a real interactive shell in the browser — arbitrary
command execution as whatever the machine's account can do:

- **Its own dedicated permission**, `ACTION_TERMINAL` — not folded into
  `ACTION_UPDATES` or `MACHINE_MANAGE`, must be granted explicitly.
- **Same pinned-fingerprint requirement as every SSH action** —
  unconfirmed, no terminal.
- **Session start/end are audited, not keystrokes.** `machine.terminal.open`
  logs when the shell starts, `.close` logs the duration however it
  ends. What was typed/displayed is deliberately *not* recorded — a
  transcript of a potentially root shell would itself be sensitive.
- **A WebSocket, authenticated by hand.** Starlette never invokes
  `http`-scoped middleware for a WebSocket — no auth for free.
  `terminal_ws.py` re-implements the session-cookie lookup and
  permission check itself, closing the socket (code `1008`) before
  accepting or touching SSH on failure — never accept-then-fail. The
  page shell is separately gated by the ordinary permission/fingerprint checks.
- **A hard 2-hour session cap**, closed server-side regardless of
  activity. Connection and remote process torn down in a `finally` on
  every exit path.
- **AsyncSSH's own PTY support, not a new dependency.**
  `open_shell_session` calls `open_connection`, then
  `conn.create_process(term_type=..., term_size=..., encoding=None)`;
  `change_terminal_size` handles resize. `encoding=None` keeps the byte
  stream raw, since a terminal relays arbitrary bytes (partial UTF-8, ANSI
  escapes).
- **A simple binary/text WebSocket protocol.** Binary frames carry raw
  terminal bytes in both directions; text frames carry small JSON control
  messages — a client-sent `resize` (cols/rows) and a server-sent `error`
  for a failure before there's a PTY.
- **xterm.js, vendored locally** (MIT-licensed) with its `addon-fit` and
  `addon-canvas` — `app/web/static/js/xterm.min.js` /
  `xterm-addon-fit.min.js` / `xterm-addon-canvas.min.js`,
  `app/web/static/css/xterm.css`; never a CDN.
  `app/web/static/js/terminal.js` is this app's own CSP-safe wiring script
  (external file, no inline `<script>`).
  **`addon-canvas` specifically fixes a CSP-caused bug, not just a
  performance nicety**: xterm.js's default DOM renderer draws every ANSI
  color by injecting a `<style>` element with the whole palette as CSS
  rules — `style-src 'self'` (no `unsafe-inline`) silently blocks that, so
  `ls --color`, a colored prompt, `htop`, etc. all rendered as plain
  foreground-only text, with nothing visible anywhere except a CSP
  violation in the browser console — a CSP violation is silent at the
  Python layer (route returns 200, tests pass), exactly the class of bug
  CLAUDE.md's "verify anything CSP-adjacent in a real browser, not just by
  reading the code" rule exists for. The canvas addon draws glyph
  colors straight onto a `<canvas>` (a `fillStyle` assignment, not a
  stylesheet), which CSP's `style-src` has no say over at all —
  `term.loadAddon(new CanvasAddon.CanvasAddon())` right after `term.open()`,
  wrapped in try/catch so a browser with no 2D canvas support just keeps
  the (colorless, under this CSP) DOM renderer instead of breaking the
  whole terminal.
- **CSP: `connect-src 'self'`**, spelled out explicitly (it previously fell
  back to `default-src 'self'`); a same-origin `ws`/`wss` upgrade is
  covered by `'self'`.
- **Not exposed over the REST API.**

### 🕒 Scheduling: reusing actions, not reimplementing them

**Scheduling** runs an existing action — update, update check, reboot,
shut down — against a machine, group, or "All machines" on a cron expression.

- **An action registry, not a hardcoded list.** `register_action()`
  registers every action that exists today (`system_update`,
  `check_updates`, `force_facts_refresh`/`force_monitoring_sample` — the
  last two force a fleet-wide sweep on demand for debugging —
  `reboot`, `shutdown`, `run_command`), wrapping the same functions the
  manual buttons use. A new one needs one more call. Idempotent, called
  from `app.main`, `app.scheduling.jobs` at import time, and each forked worker child.
- **One shared implementation for "trigger this against N machines"** —
  `trigger_updates`/`trigger_check_updates`/`trigger_facts_refresh`/
  `trigger_monitoring_sample`/`send_power_to_machines` in
  `machine_actions`, no `Request`, no queue handle. A scheduled run and a
  human click take the exact same path, including skip-unpinned behavior.
- **A fixed one-minute tick** — cron is minute-grained, so
  `run_due_scheduled_tasks` is a plain `crontab()` Beat entry. Each task
  keeps a denormalized `next_run_at` (computed on create/edit/enable,
  advanced immediately when it fires) so the tick is one indexed query.
  Advancing *before* the action runs stops a slow action re-enqueuing on the next tick.
- **No per-run history** — a firing records a short `last_run_summary` +
  `last_run_at`; the action itself already has its own record.
- **Always UTC, no per-schedule timezone.**
- **Reboot/shutdown are schedulable and not re-confirmed at fire time** —
  flagged `destructive=True`, surfaced with a ⚠ on the form.
- **Target encoding: one `<select>`** — type + id folded into one string
  (`"all"`, `"machine:<uuid>"`, `"group:<uuid>"`), no client-side JS needed.

