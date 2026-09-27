# 📝 Audit Log

*Who did what, with what outcome, when — tamper-evident, exportable and
optionally forwarded to a SIEM. Also the Dashboard's daily trend snapshot.*

### 📝 Audit log: who, what, outcome, when

**Audit** (`audit.view`, not scoped by machine group) records every
human- or schedule-initiated change and every safeguard that refused one
(wrong typed confirmation, unpinned host key, CSRF rejection, bad
self-registration token, failed or locked-out login), with the actor,
source IP and time.

- `actor` is a username, or a fixed label for automatic runs ("scheduler
  (automatic)", "retention policy (automatic)"); empty only before login.
- `app.audit.log_event()` is the only write path, called **after** the
  action's own commit, so a logging failure can never undo the action.
- Targets are stored as `target_type`/`target_id` plus a `target_label`
  snapshot — not a foreign key, since things get renamed and deleted.
- **Unattended periodic sweeps aren't logged** (reachability, facts,
  update checks, config drift) — only what people and schedules did.
- `summary` is stored in **English** (exports, syslog and the API carry it
  as-is); the pages show other languages the translated
  `audit.action_label.<code>`, with the English text on hover.

### 🌍 GeoIP

Optional (**Settings → Integrations → GeoIP**): a public source IP is
resolved to country/city once, at write time, and shown next to the IP
and in exports. You supply the download URL for a MaxMind-format database
(e.g. a GeoLite2 permalink, stored encrypted); it's refreshed on your
chosen interval or with *Download now*. Private addresses are never
looked up, and geo fields are not part of the hash chain.

### Hash chain: what it guarantees

Each entry stores `sequence`, `prev_hash` and `entry_hash` — SHA-256 over
its canonical fields plus the previous hash — so editing or deleting an
entry breaks the chain; the newest hash is also kept in
`AuditChainState`, so deleting the latest entries is caught too. Writes
are serialized with `SELECT … FOR UPDATE` on that row. **Verify** on
Settings → Security (or `POST /api/v1/audit/verify`) walks the chain and
is itself audited. It detects corruption and casual tampering, not a
database superuser who recomputes the chain. Entries from before the
chain existed are skipped.

### Audit log retention

**Settings → Security → Audit log retention** (default 90 days, empty =
forever); a daily job removes only the oldest entries, so the remaining
chain still verifies. The purge is itself audited (`audit_log.purge`).

### 📊 Dashboard trends

One `FleetSnapshot` row per day (02:00 UTC) of the same counts the
Dashboard shows live (both use `compute_fleet_stats`), kept for
`dashboard_trends_retention_days` (default 90). The chart appears once
two snapshots exist; `GET /api/v1/dashboard/trends` returns the series.

### Export and syslog

- **Export**: `GET /audit/export?format=csv|json` with the page's filters
  (including an exact `target_type` + `target_id`, used by "audit history
  for this machine"); formula-like cells are neutralized in CSV; each
  export is audited. REST: `GET /api/v1/audit`, `/api/v1/audit/export`.
- **Syslog**: every entry is mirrored right after its commit over UDP, TCP
  or TLS (RFC 5424, JSON message) — best effort, so an unreachable SIEM
  never blocks the audited action. Configured in Settings → Integrations
  (web-only).
