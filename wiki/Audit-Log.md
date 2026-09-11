# 📝 Audit Log

*Who did what, its outcome, and when — the tamper-evident trail, its
retention, export, and syslog/SIEM forwarding, plus the Dashboard's daily
trend snapshot (same retention-and-purge shape, grouped here for that
reason). Split out of [Architecture](Architecture.md) so this one topic
is easier to search — start there for the rest (auth/RBAC, machine
management, notifications, HTTP hardening).*

### 📝 Audit log: who, what, outcome, when

**Audit** records what happened, its outcome, source IP, and when — for
essentially every mutating action and every safeguard that blocked one
(a typed confirmation mismatch, an unpinned host key, a bad
self-registration token, a rejected form, a failed/locked-out login).

- **`actor`** carries a human username, or a fixed label ("scheduler
  (automatic)", "retention policy (automatic)") for background jobs —
  `None` only for pre-login events. `ip_address` recorded alongside for
  every HTTP-triggered event.
- **One write path, called after the fact, never before.** `log_event()`
  is the only thing creating rows, commits independently, always called
  *after* the caller's own commit — a logging failure can never roll back
  the action it describes (caught and swallowed, logged at `ERROR`).
- **Not a foreign key** — `target_type`/`target_id` are plain strings,
  `target_label` a snapshot at event time, since a machine/group can be
  renamed or deleted later.
- **Scheduled firings logged with a fixed actor** — no HTTP request, so no IP.
- **Routine sweeps aren't logged** — `ping_all_machines` and periodic
  facts/update-check sweeps would flood it with heartbeats; only a
  human/schedule-triggered action gets an entry.
- **CSRF rejections *are* logged** — `verify_csrf` takes its own
  `db` dependency and calls `log_event` (`auth.csrf_rejected`, `DENIED`)
  before raising the 403 — see "CSRF protection" below.
- **No pagination cursor beyond offset.**

### Audit log integrity: hash chaining, and its actual guarantee

Every entry is linked into a hash chain (`sequence`, `prev_hash`,
`entry_hash`) so altering/deleting one is detectable:

- **What `entry_hash` covers** — SHA-256 over a canonical JSON
  serialization of the entry's fields, concatenated with the *previous*
  entry's hash. Change anything and the hash no longer matches; delete
  an entry and the next one's `prev_hash` points at nothing.
  `verify_chain` walks every entry, recomputes, compares the newest
  against `AuditChainState.last_hash` (catches deleting the *most
  recent* entries outright). Reachable from Settings, itself logged as `audit_log.verify`.
- **`created_at` assigned in Python, not the database** — every other
  timestamp uses `server_default=now()`; this one can't, since
  `log_event` needs the exact value *before* insert to hash it.
- **Serialized through one locked row** — `AuditChainState` is a
  dedicated one-row table, read with `SELECT ... FOR UPDATE` and held
  for the rest of the transaction, so two racing writes (different
  requests, or different processes — web + every forked worker) can
  never link to the same previous hash. `FOR UPDATE` is a no-op on SQLite (tests), fine there.
- **What this doesn't protect against** — direct DB access (a superuser
  editing rows and recomputing the chain) isn't defended against, only
  internal self-consistency. Catches accidental corruption and a casual
  edit/deletion, not a substitute for restricting DB access.
- **Entries from before this feature have no chain** — nullable fields, `verify_chain` skips them rather than flagging broken.

### Audit log retention: the first setting editable through the UI

`audit_log_retention_days`, set from Settings, controls how many days
`purge_old_audit_log_entries` keeps on a daily sweep. Defaults to **90
days**, same as the operational-data retention settings below; `None`
(settable from the same Settings field) means keep forever.

The first value editable at runtime through the UI rather than fixed at
deploy time via `.env`. Purging only removes the *oldest* rows; never
touches `AuditChainState` or the newest entries, so it can't invalidate
`verify_chain` for what remains. The purge is itself logged
(`audit_log.purge`, actor "retention policy (automatic)").

### 📊 Dashboard trends: a daily snapshot

`FleetSnapshot` is one row per calendar day of the fleet-wide counts the
Dashboard shows live. The live Dashboard and the daily snapshot job (a
fixed 02:00 UTC tick) both go through `compute_fleet_stats`, so they
can't define these counts differently. Idempotent per calendar day
(checked, then enforced by a unique constraint).

`dashboard_trends_retention_days` + `purge_old_fleet_snapshots` (03:05
UTC) follow the audit-retention pattern, default **90 days**.

Renders only once at least two snapshots exist. Generated server-side as
inline SVG using only presentation attributes — never `style=`/`<style>`
— no CSP exception, no charting library needed. `GET
/api/v1/dashboard/trends` exposes the same series read-only.

### Audit log export and syslog forwarding

`GET /audit/export?format=csv|json` respects the same filters as the
list view, streams every match as a download — a plain link, not a POST;
its only side effect is an `audit_log.export` entry. Not paginated —
fetches every matching row in one request.

`target_type`+`target_id` is an *exact* match, unlike `q`'s free-text
match on `target_label` (a point-in-time snapshot that can miss a
since-renamed target) — the "view audit history for this machine" link
uses it. One shared filter function for web and REST, so list and export never drift.

`forward_to_syslog` is a live *mirror*, not an alternative record —
`log_event` calls it once per entry, right after that entry's commit,
using whatever `syslog_*` is configured (UDP, TCP, or TCP-over-TLS —
RFC 5424 format, RFC 6587 framing for TCP). Best-effort, fire-and-forget
— an unreachable/slow/misconfigured SIEM must never block or fail the
action being audited, so any delivery failure is caught and swallowed.
Blocking socket I/O runs via `asyncio.to_thread`, same pattern LDAP's
synchronous calls use. The MSG part is a compact JSON object, not
free-text `key="value"` pairs — a receiver's own parser (or `jq`) needs
no bespoke grammar for it.

