# 🖥️ Host requirements & scaling to a large fleet

This page is about **debcontrol's own host(s)** — the machine(s) running
the Docker Compose stack (web, worker, beat, Postgres, Redis) — not the
Debian/Ubuntu machines it manages. For those, see
[Machine Requirements](Machine-Requirements.md).

Two different things drive resource needs here, and they scale
independently:

- **Fleet size** (how many machines are managed) drives Postgres row counts,
  Celery task volume, and SSH connection concurrency.
- **Concurrent admin usage** (how many people have the UI open at once)
  drives web-process request/DB-connection load — self-polling panels (see
  [Architecture](Architecture.md)) mean an open browser tab keeps making
  small requests every 20-30s even when nobody's clicking anything.

A fleet of a few dozen machines with one admin barely needs tuning beyond
the defaults. A fleet in the hundreds or thousands, or several admins
working at once, needs the knobs below actually turned.

## 📊 Quick reference

Rough sizing for the whole stack (all services combined) at a few fleet
sizes, assuming default sweep intervals (facts/packages/services/update-
check every 10 minutes, monitoring every 2 minutes, reachability every
minute) and a handful of concurrent admins. Treat these as a starting
point, not a guarantee — the "how to compute this yourself" section below
explains where the numbers come from so you can adjust for your own
intervals/usage.

| Fleet size | vCPU | RAM | Postgres storage (retention windows below) | Notes |
|---|---|---|---|---|
| Up to 100 | 2 | 4 GB | 1–2 GB | Defaults are fine everywhere. |
| 100–500 | 4 | 8 GB | 5–8 GB | Raise `DB_POOL_SIZE`/`DB_MAX_OVERFLOW`; raise `FACTS_REFRESH_INTERVAL_SECONDS` (e.g. back to the old 3600s default) or scale `worker` out — the default 600s cadence outruns one worker replica's headroom past roughly 200 machines (see below). |
| 500–1,500 | 4–8 | 8–16 GB | 15–22 GB | All of the above, plus: raise `REACHABILITY_CHECK_CONCURRENCY`; raise Postgres `max_connections`. |
| 1,500–5,000+ | 8–16 | 16–32 GB | 50–70 GB+ | All of the above, plus: dedicated Postgres tuning (below), multiple `worker` replicas, and a closer look at monitoring/update-run retention (below) — monitoring history is the dominant contributor to storage at this scale. |

"Postgres storage" above assumes the default 90-day retention on
monitoring history, dashboard trends, and update-run history, and no
retention cap on the audit log (the audit log's own growth depends on
admin/API activity, not fleet size, and is bounded by `Settings →
Security → Audit log`'s own retention setting if you set one). Monitoring
history (see "Disk growth" below) is by far the largest of these at any
real fleet size — shorten its retention first if storage is tight.

## 🧮 How to compute this yourself

### 1. The reachability sweep must finish inside its own interval

`ping_all_machines` (Celery Beat, every `REACHABILITY_CHECK_INTERVAL_SECONDS`,
default 60s) checks every machine with a bounded number running at once
(`REACHABILITY_CHECK_CONCURRENCY`, default 20) — a semaphore around a plain
TCP connect attempt per machine, not a thread/process count.

Worst case, every machine currently times out (`SSH_CONNECT_TIMEOUT`,
default 10s — the reachability check reuses this as its own connect
timeout) rather than answering instantly:

```
sweep duration (worst case) ≈ ceil(machine_count / concurrency) × SSH_CONNECT_TIMEOUT
```

Beat does **not** skip or coalesce a sweep that's still running when the
next tick fires — if a sweep consistently overruns the interval, sweeps
pile up rather than one replacing the next. Solve for the concurrency you
need to comfortably fit inside the interval, with some margin (real fleets
are never 100% down at once, but plan for it anyway):

```
concurrency ≥ machine_count × SSH_CONNECT_TIMEOUT / (REACHABILITY_CHECK_INTERVAL_SECONDS × safety_margin)
```

Example: 2,000 machines, default 10s timeout, default 60s interval, a 2×
safety margin → `concurrency ≥ 2000 × 10 / (60 × 2) ≈ 167`. Round up and set
`REACHABILITY_CHECK_CONCURRENCY=200` in `.env`.

### 2. Worker throughput must keep up with the fan-out sweeps

`refresh_all_machine_facts`, `refresh_all_machine_packages`,
`refresh_all_machine_services`, `refresh_all_machine_readiness`, and
`check_all_machine_updates` each enqueue one Celery task **per machine**,
every `FACTS_REFRESH_INTERVAL_SECONDS` (default 600s, 10 minutes) — five
SSH round trips per machine per interval, fanned out rather than awaited
inline (see
[Architecture](Architecture.md#background-tasks-celery-and-celery-beat)),
so one slow/unreachable machine never holds up the rest. `monitor_all_
machines` is the same idea on its own, much shorter cadence
(`MONITORING_INTERVAL_SECONDS`, default 120s) — a sixth, lighter round
trip (see that task's own `MONITORING_COMMAND`, a `sleep 1` plus a few
cheap reads, versus facts/packages' several commands) that, because it
ticks so much more often, is usually the *larger* contributor to total
worker load at fleet scale even though each individual task is cheaper.

```
tasks per hour ≈ 5 × machine_count × (3600 / FACTS_REFRESH_INTERVAL_SECONDS)
                + machine_count × (3600 / MONITORING_INTERVAL_SECONDS)
worker capacity per hour ≈ (worker replicas × --concurrency) × (3600 / avg_task_seconds)
```

A handful of noisy or low-priority machines don't have to share the fleet's
global cadence: **Machine → Settings → Overwrite check intervals** lets one
machine raise its own reachability/facts interval above the instance-wide
default (never below the sweep's own tick rate — a machine can be checked
*less* often than the fleet, never more often than Celery Beat's own tick).
Useful for a machine that's expected to be offline for long stretches, or
one you just don't need fresh facts on as often as everything else — it
stops eating a sweep slot every tick without touching the `.env` default
for the rest of the fleet.

A typical facts/packages/update-check task (SSH connect + a handful of
remote commands) takes on the order of 1-5 seconds against a healthy,
nearby machine — call it 3s for planning. The bundled `worker` service
defaults to one replica at `--concurrency=10`, i.e. roughly 12,000 tasks/
hour of headroom at that estimate. At the default cadences (`60 ×
machine_count` tasks/hour — the formula above with 600s facts and 120s
monitoring plugged in) that's comfortable up to roughly 200 machines
before the sweeps can't finish inside their own interval; lengthen
`FACTS_REFRESH_INTERVAL_SECONDS` for a larger fleet before reaching for
more worker capacity, since facts/packages/services/readiness/update-checks
changing every 10 minutes is rarely necessary at scale.

Past that, scale **out** (more `worker` replicas — safe, see the comment on
that service in `docker-compose.yml`) or **up** (`--concurrency=N` per
replica, CPU/RAM permitting):

```bash
docker compose up -d --scale worker=3
```

Never scale `beat` past one replica — every replica would publish the same
schedule, multiplying every sweep and daily purge.

### 3. Web process DB connections must cover concurrent admins

Every open browser tab on a machine/settings page keeps several panels
self-polling every 20-30s (see [Architecture](Architecture.md)) — each poll
is one lightweight request holding a DB connection briefly, not one long-
lived connection per tab, but at enough concurrent admins the web process's
own connection pool (`DB_POOL_SIZE` + `DB_MAX_OVERFLOW`, defaults 10 + 20)
can still run out under a burst. If requests start visibly queuing/slowing
under load with nothing else obviously wrong, raise both, and raise
Postgres' own `max_connections` (image default: 100) to comfortably exceed:

```
DB_POOL_SIZE + DB_MAX_OVERFLOW                         (web process)
+ (worker replicas × --concurrency)                    (worker's NullPool — see below)
+ a handful for `beat`/`migrate`/an interactive `psql`
```

The worker's own DB engine deliberately uses `NullPool` (a fresh connection
per task, closed right after — see
[Architecture](Architecture.md#fork-safety-the-db-engine-is-rebuilt-in-every-worker-child)
for why), so its contribution to that total is bounded by how many tasks
are running at once (`worker replicas × --concurrency`), not by anything
that grows with fleet size on its own.

Raise Postgres' `max_connections` via a `command:` override on the `db`
service in `docker-compose.yml`:

```yaml
db:
  command: ["postgres", "-c", "max_connections=300", "-c", "shared_buffers=1GB"]
```

(`shared_buffers` — standard Postgres guidance is roughly 25% of the
container's available RAM; adjust to match whatever you actually give the
`db` container.)

## 💾 Disk growth

Two tables dominate storage as the fleet grows; everything else (accounts,
roles, groups, scheduled tasks, the machine rows themselves) stays small
regardless of fleet size.

- **`machine_packages`** — one row per installed package per machine (apt +
  flatpak + snap), replaced wholesale on every packages refresh (not a
  history — always "what's installed right now"). A typical Debian/Ubuntu
  server has somewhere from a couple hundred to (with a heavier desktop-ish
  install) over a thousand packages. At ~150 bytes/row plus index overhead,
  budget roughly 100-250 KB per machine — 100-250 MB at 1,000 machines,
  0.5-1.2 GB at 5,000.
- **`machine_update_runs`** — one row per triggered update, each holding up
  to ~200 KB of stored apt/flatpak/snap output (`_MAX_STORED_OUTPUT_CHARS`
  in `app/tasks/jobs.py`). This is the one that can genuinely run away on a
  large fleet with **recurring scheduled updates** (see Scheduling) — it
  has its own retention setting (`Settings → Security → Update run
  history`, defaults to 90 days, same reasoning as Dashboard trends: this
  is operational output, not the compliance record — the fact that an
  update was *triggered* stays in the audit log regardless of this
  setting) with a daily purge job. Tighten it (e.g. 30 days) for a large
  fleet running updates often; worst case at the 90-day default, weekly
  scheduled updates, 200KB every time: `machine_count × ~13 runs × 200KB` —
  2.6 GB at 1,000 machines, 13 GB at 5,000. Real output is usually far
  smaller than the 200KB cap, but plan for the cap if you can't predict how
  chatty a given fleet's apt runs will be.

- **`machine_monitoring_samples`** — the Monitoring tab's CPU/RAM/disk
  history, unlike the two above genuinely a history (one row appended per
  machine per `MONITORING_INTERVAL_SECONDS` tick, 2 minutes by default —
  ~720 rows/machine/day), not a replaced snapshot. At ~150 bytes/row this
  is the fastest-growing table by far without its retention setting
  (`Settings → Security → Monitoring history`, defaults to 90 days, also
  overridable per machine): `machine_count × 720/day × 150 bytes × retention_days`
  — roughly 1 GB/day per 10,000 machines at the default settings, so 90
  GB at the 90-day default retention. Shorten the interval's *retention*
  (not the sample interval itself, which trades off against how fine-
  grained the trend graphs are) first if this table is the one growing
  fastest for you; `machine_services` (a replaced snapshot, refreshed on
  the facts cadence like `machine_packages`) stays small by comparison.

The audit log is hash-chained and append-only by design (tampering breaks
the chain from that point on — see
[Architecture](Architecture.md#-audit-log-who-what-outcome-when)); its
growth tracks admin/API/scheduled-action activity, not fleet size directly,
and has its own independent retention setting.

## 🚦 Signs you're under-provisioned

- **Beat/worker logs show sweeps overlapping** (a `ping_all_machines` or
  `refresh_all_machine_*` task still running when the next one for the
  same job fires) — raise `REACHABILITY_CHECK_CONCURRENCY` or scale
  `worker` per the formulas above.
- **A machine's Facts/Updates panel lags noticeably behind the configured interval**
  — the fan-out sweep can't keep up with `FACTS_REFRESH_INTERVAL_SECONDS`;
  scale `worker` out or up, or lengthen the interval.
- **Pages feel sluggish with nothing failing outright** — check Postgres'
  own connection count (`SELECT count(*) FROM pg_stat_activity;`) against
  its `max_connections`; raise `DB_POOL_SIZE`/`DB_MAX_OVERFLOW` and
  `max_connections` together per the formula above.
- **`pg_data` growing faster than expected** — check `machine_update_runs`'
  row count and average `output` length; tighten its retention setting.

## 🖧 Network

Bandwidth is negligible at any fleet size discussed here — each SSH round
trip is a handful of short remote commands (facts/packages/update-check)
or a bounded apt transcript, not a bulk data transfer. The thing that
actually needs headroom is **concurrent SSH connections outbound from the
`worker` container(s)** during a fan-out sweep — sized by the same
`worker replicas × --concurrency` figure used for DB connections above,
not by fleet size on its own.
