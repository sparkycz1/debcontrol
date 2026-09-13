# 🖥️ Host requirements & scaling to a large fleet

*Sizing the thing that watches your fleet, not the fleet itself.*

This page is about **debcontrol's own host(s)** — web/worker/beat/
Postgres/Redis — not the Debian/Ubuntu machines it manages (that's
[Machine Requirements](Machine-Requirements.md)).

Two independent drivers:

- **Fleet size** → Postgres row counts, Celery task volume, SSH concurrency.
- **Concurrent admin usage** → web-process request/DB-connection load —
  self-polling panels mean an open tab keeps making small requests every
  20-30s even when nobody's clicking.

A few dozen machines, one admin: defaults are fine. Hundreds/thousands,
or several admins at once: turn the knobs below.

## 📊 Quick reference

Rough whole-stack sizing at default sweep intervals (facts/packages/
services/update-check every 10 min, monitoring every 2 min, reachability
every minute) and a handful of admins. A starting point, not a
guarantee — "how to compute this yourself" below shows the math.

| Fleet size | vCPU | RAM | Postgres storage (retention windows below) | Notes |
|---|---|---|---|---|
| Up to 100 | 2 | 4 GB | 1–2 GB | Defaults are fine everywhere. |
| 100–500 | 4 | 8 GB | 5–8 GB | Raise `DB_POOL_SIZE`/`DB_MAX_OVERFLOW`; raise `FACTS_REFRESH_INTERVAL_SECONDS` (e.g. back to the old 3600s default) or scale `worker` out — the default 600s cadence outruns one worker replica's headroom past roughly 200 machines (see below). |
| 500–1,500 | 4–8 | 8–16 GB | 15–22 GB | All of the above, plus: raise `REACHABILITY_CHECK_CONCURRENCY`; raise Postgres `max_connections`. |
| 1,500–5,000+ | 8–16 | 16–32 GB | 50–70 GB+ | All of the above, plus: dedicated Postgres tuning (below), multiple `worker` replicas, and a closer look at monitoring/update-run retention (below) — monitoring history is the dominant contributor to storage at this scale. |

"Postgres storage" assumes default 90-day retention on monitoring
history, dashboard trends, and update-run history, and no cap on the
audit log (grows with admin/API activity, not fleet size — bounded by
its own retention setting if you set one). Monitoring history dominates
at any real scale — shorten its retention first if storage is tight.

## 🧮 How to compute this yourself

> [!NOTE]
> The settings named below by their old environment-variable names
> (`REACHABILITY_CHECK_INTERVAL_SECONDS`, `REACHABILITY_CHECK_CONCURRENCY`,
> `SSH_CONNECT_TIMEOUT`, `FACTS_REFRESH_INTERVAL_SECONDS`,
> `MONITORING_INTERVAL_SECONDS`) are all set from **Settings → Checks &
> retention** now, not `.env` — see [Installation](Installation.md). The
> names and the math below are otherwise unchanged.

### 1. The reachability sweep must finish inside its own interval

`ping_all_machines` (Beat, every `REACHABILITY_CHECK_INTERVAL_SECONDS`,
default 60s) checks every machine with a bounded concurrency
(`REACHABILITY_CHECK_CONCURRENCY`, default 20) — a semaphore, not a
thread/process count. Worst case (every machine times out at
`SSH_CONNECT_TIMEOUT`, default 10s):

```
sweep duration (worst case) ≈ ceil(machine_count / concurrency) × SSH_CONNECT_TIMEOUT
```

Beat never skips/coalesces an overrunning sweep — they pile up instead.
Solve for the concurrency that fits comfortably inside the interval:

```
concurrency ≥ machine_count × SSH_CONNECT_TIMEOUT / (REACHABILITY_CHECK_INTERVAL_SECONDS × safety_margin)
```

Example: 2,000 machines, 10s timeout, 60s interval, 2× margin →
`≥ 2000 × 10 / (60 × 2) ≈ 167`. Round up: `REACHABILITY_CHECK_CONCURRENCY=200`.

### 2. Worker throughput must keep up with the fan-out sweeps

Five sweeps (`refresh_all_machine_facts`/`_packages`/`_services`/
`_readiness`, `check_all_machine_updates`) each enqueue one task **per
machine** every `FACTS_REFRESH_INTERVAL_SECONDS` (default 600s) — fanned
out, never awaited inline, so one slow machine can't hold up the rest.
`monitor_all_machines` is a sixth, lighter, much-more-frequent round trip
(`MONITORING_INTERVAL_SECONDS`, default 120s) — cheaper per-task, but
usually the *larger* contributor to total worker load simply because it ticks so often.

```
tasks per hour ≈ 5 × machine_count × (3600 / FACTS_REFRESH_INTERVAL_SECONDS)
                + machine_count × (3600 / MONITORING_INTERVAL_SECONDS)
worker capacity per hour ≈ (worker replicas × --concurrency) × (3600 / avg_task_seconds)
```

A noisy/low-priority machine doesn't have to share the global cadence:
**Machine → Settings → Overwrite check intervals** raises just its own
interval (never below Beat's tick rate). Good for one that's often
offline, or doesn't need facts as fresh as everything else.

A typical facts/packages/update-check task takes ~1-5s against a healthy
nearby machine (call it 3s). Default `worker` (one replica,
`--concurrency=10`) ≈ 12,000 tasks/hour of headroom. At default cadences
(`60 × machine_count` tasks/hour) that's comfortable to roughly 200
machines before sweeps can't finish in their own interval — lengthen
`FACTS_REFRESH_INTERVAL_SECONDS` before reaching for more worker capacity.

Past that, scale **out** (more `worker` replicas — safe) or **up**
(`--concurrency=N`, CPU/RAM permitting):

```bash
docker compose up -d --scale worker=3
```

Never scale `beat` past one replica — every replica publishes the same
schedule, multiplying every sweep and daily purge.

### 3. Web process DB connections must cover concurrent admins

Self-polling panels mean each open tab holds a DB connection briefly
every 20-30s (not one long-lived connection per tab) — enough concurrent
admins can still exhaust the web process's pool (`DB_POOL_SIZE` +
`DB_MAX_OVERFLOW`, defaults 10 + 20). Requests visibly queuing/slowing
with nothing else wrong? Raise both, and Postgres' `max_connections`
(default 100) to comfortably exceed:

```
DB_POOL_SIZE + DB_MAX_OVERFLOW                         (web process)
+ (worker replicas × --concurrency)                    (worker's NullPool — see below)
+ a handful for `beat`/`migrate`/an interactive `psql`
```

The worker's `NullPool` (fresh connection per task, see
[Architecture](Architecture.md#fork-safety-the-db-engine-is-rebuilt-in-every-worker-child))
bounds its contribution by tasks running at once, not fleet size directly.

Raise `max_connections` via a `command:` override on `db` (`docker-compose.yml`'s
`db` service already sets `shared_buffers`/`effective_cache_size`/`work_mem`/
`maintenance_work_mem`/the two `autovacuum_*_scale_factor`s from `.env`
variables — `POSTGRES_SHARED_BUFFERS` etc., see `.env.example` — each
defaulting to Postgres' own stock value, so add `max_connections` to that
same list rather than a separate override):

```
# .env
POSTGRES_SHARED_BUFFERS=1GB
```

(`shared_buffers` — standard Postgres guidance is roughly 25% of the
container's available RAM; adjust to match whatever you actually give the
`db` container. `max_connections` itself isn't one of the pre-wired knobs —
add it with your own `command:` override on `db` if you need to raise it
above Postgres' default 100.) Lowering the two `autovacuum_*_scale_factor`
knobs (stock defaults 0.2/0.1) below their stock values makes autovacuum
run more often on large, frequently-purged tables like
`machine_monitoring_samples`/`notification_logs`/`audit_log_entries` —
worth doing at fleet sizes where the daily retention purges delete a large
fraction of those tables' rows each night, so dead tuples don't accumulate
between autovacuum runs.

Similarly, `worker`'s `--concurrency` (default 10, see point 2 above) is
set from `CELERY_WORKER_CONCURRENCY` in `.env` — raise it there instead of
editing `docker-compose.yml` directly.

## 💾 Disk growth

Two tables dominate as the fleet grows; everything else (accounts,
roles, groups, scheduled tasks, machine rows) stays small regardless.

- **`machine_packages`** — one row per installed package (apt+flatpak+snap),
  replaced wholesale each refresh (always "right now", not a history).
  ~150 bytes/row → roughly 100-250 KB/machine (a couple hundred to 1000+
  packages) — 100-250 MB at 1,000 machines, 0.5-1.2 GB at 5,000.
- **`machine_update_runs`** — one row per triggered update, up to ~200 KB
  of stored output each (`_MAX_STORED_OUTPUT_CHARS`). Can genuinely run
  away with **recurring scheduled updates** — own retention setting
  (`Settings → Security`, default 90 days, daily purge; the *trigger*
  stays in the audit log regardless). Tighten it for a large,
  often-updating fleet. Worst case at 90 days/weekly updates/200KB:
  `machine_count × ~13 runs × 200KB` — 2.6 GB at 1,000 machines, 13 GB at
  5,000 (real output is usually well under the cap).
- **`machine_monitoring_samples`** — genuinely a history (one row per
  `MONITORING_INTERVAL_SECONDS` tick, ~720/machine/day at the 2-min
  default), the fastest-growing table by far. Own retention setting
  (default 90 days, per-machine overridable):
  `machine_count × 720/day × 150 bytes × retention_days` — ~1 GB/day per
  10,000 machines, 90 GB at 90-day default retention. Shorten *retention*
  first (not the sample interval, which trades off trend-graph
  granularity); `machine_services` (a replaced snapshot) stays small.
  A second, cheaper lever before reaching for either: **downsampling**
  (`Settings → Checks & retention → Monitoring`,
  `AppSettings.monitoring_downsample_after_days`/`_interval_minutes`,
  default 7 days / 60-minute buckets,
  `app.tasks.jobs.downsample_old_monitoring_samples`) thins samples older
  than a few days down to one per bucket instead of deleting them outright
  — a chart already buckets old data for display (`app.services.
  monitoring_history._bucket_average`), so full-resolution rows from weeks
  ago cost storage for detail nothing renders. Shrinks the table without
  shortening retention or losing trend shape; tighten retention on top of
  that if storage is still tight.

The audit log is hash-chained and append-only (tampering breaks the
chain from that point — see
[Architecture](Audit-Log.md#-audit-log-who-what-outcome-when)); grows
with activity, not fleet size, with its own retention setting.

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

Bandwidth is negligible at any fleet size here — each SSH round trip is a
handful of short commands or a bounded apt transcript, not bulk data.
What actually needs headroom: **concurrent outbound SSH connections from
`worker`** during a fan-out sweep — sized by `worker replicas ×
--concurrency`, same as the DB-connection figure above, not fleet size on its own.
