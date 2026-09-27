# 🖥️ Host requirements & scaling to a large fleet

*Sizing debcontrol's own host (web, worker, beat, Postgres, Redis) — for the
managed machines see [Machine Requirements](Machine-Requirements.md).*

Load grows with **fleet size** (rows, Celery tasks, SSH concurrency) and
**concurrent admins** (every open tab polls every 20–60 s). A few dozen
machines and one admin run fine on the defaults.

## 📊 Quick reference

At default intervals (facts, packages, services and update checks every
10 min, monitoring every 2 min, reachability every minute) and 90-day
retention:

| Fleet | vCPU | RAM | Postgres storage | What to change |
|---|---|---|---|---|
| ≤ 100 | 2 | 4 GB | 1–2 GB | nothing |
| 100–500 | 4 | 8 GB | 5–8 GB | raise `DB_POOL_SIZE`/`DB_MAX_OVERFLOW`; above ~200 machines lengthen the facts interval or add a worker |
| 500–1 500 | 4–8 | 8–16 GB | 15–22 GB | plus reachability concurrency and Postgres `max_connections` |
| 1 500–5 000+ | 8–16 | 16–32 GB | 50–70 GB+ | plus Postgres tuning, several workers, shorter monitoring retention / downsampling |

Monitoring history dominates storage at every real scale.

## 🧮 The math

The intervals, timeouts and concurrency below are set in **Settings →
Checks & retention** (the names are the old environment-variable names).

**1. The reachability sweep must fit inside its interval.** It checks every
machine with a bounded concurrency (default 20); worst case every machine
times out:

```
sweep ≈ ceil(machines / concurrency) × SSH_CONNECT_TIMEOUT
concurrency ≥ machines × SSH_CONNECT_TIMEOUT / (REACHABILITY_CHECK_INTERVAL_SECONDS × 2)
```

2 000 machines, 10 s timeout, 60 s interval → concurrency ≈ 170 (use 200).

**2. Workers must keep up with the fan-out.** Five sweeps enqueue one task
per machine every facts interval, and monitoring one per machine every
monitoring interval:

```
tasks/hour ≈ 5 × machines × 3600 / FACTS_REFRESH_INTERVAL_SECONDS
           + machines × 3600 / MONITORING_INTERVAL_SECONDS
capacity/hour ≈ worker replicas × concurrency × 3600 / avg_task_seconds
```

One worker (`CELERY_WORKER_CONCURRENCY=10`, ~3 s per task) handles about
12 000 tasks/hour — comfortable up to roughly 200 machines at default
intervals. Beyond that, lengthen intervals (also per machine: **Machine →
Settings → Overwrite check intervals**) or scale out:

```bash
docker compose up -d --scale worker=3
```

Never scale `beat` beyond one.

**3. Database connections.** Postgres `max_connections` (default 100) must
exceed

```
DB_POOL_SIZE + DB_MAX_OVERFLOW          (web, default 10 + 20)
+ worker replicas × concurrency          (NullPool: one per running task)
+ a few for beat, migrate and psql
```

Postgres tuning comes from `.env` and is active from the first start
(defaults sized for ~100 machines): `POSTGRES_SHARED_BUFFERS` (256MB),
`_EFFECTIVE_CACHE_SIZE` (768MB), `_WORK_MEM` (8MB), `_MAINTENANCE_WORK_MEM`
(128MB) and lowered autovacuum scale factors (0.05 / 0.02) so the nightly
purges don't leave dead rows behind. For a bigger host, e.g.:

```
POSTGRES_SHARED_BUFFERS=1GB        # ~25 % of the db container's RAM
POSTGRES_EFFECTIVE_CACHE_SIZE=3GB
POSTGRES_WORK_MEM=16MB
POSTGRES_MAINTENANCE_WORK_MEM=256MB
```

`max_connections` needs your own `command:` override on `db`.

## 💾 Disk growth

- **`machine_monitoring_samples`** — the big one: ~720 rows per machine per
  day at 2-minute sampling (~1 GB/day per 10 000 machines). Use
  **downsampling** first (Settings → Checks & retention → Monitoring,
  default: after 7 days keep one sample per 60 min — charts already
  average old data), then shorter retention (also per machine).
- **`machine_update_runs`** — up to ~200 KB of output per run; frequent
  scheduled updates add up. Retention in Settings → Checks & retention
  (default 90 days).
- **`machine_packages`** — replaced on each refresh, ~100–250 KB per
  machine.
- The audit log grows with activity, not fleet size, and has its own
  retention ([Audit Log](Audit-Log.md)).

## 🚦 Signs you're under-provisioned

- Sweeps overlap in the worker logs → raise reachability concurrency or
  add workers.
- Facts/updates lag behind their interval → add workers or lengthen the
  interval.
- Pages slow with nothing failing → compare `SELECT count(*) FROM
  pg_stat_activity;` with `max_connections`; raise the pool and the limit
  together.
- `pg_data` growing fast → check monitoring and update-run retention.

## 🖧 Network

Bandwidth is negligible. What needs headroom is concurrent outbound SSH
from `worker` (replicas × concurrency). Periodic checks reuse one open
connection per machine (Machine Management → *Keeping the journal quiet*),
so steady-state logins stay low.
