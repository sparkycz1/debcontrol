# 🔔 Notifications

*Rules that send an email, webhook or push message when something happens
on the fleet: events, conditions, recipients, scope, templates, delivery
history and maintenance windows. See [Architecture](Architecture.md) for
the rest.*

`/notifications` (`notification.view` to see, `notification.manage` to
change — separate from settings and user management) holds the **rules**,
`/notifications/templates` the wording, `/notifications/history` every
delivery attempt. Everything is also in the REST API (bottom).

## Rules

A `NotificationRule` has a unique `name`, `description`, `enabled`, the
**events** that fire it, optional **conditions**, **recipients**,
**scope** and a **delivery channel**.

- **Recipients** (email only): listed users plus every active account
  holding one of the listed **roles**, re-evaluated at each firing and
  deduplicated. Accounts that are disabled or have no email
  (`User.email`, set on **My account** or by an admin; not used for
  login) are skipped.
- **Scope**: machines and/or machine groups. Empty = every machine. Events
  that aren't about a machine (fleet summary, endpoint checks) always
  match.
- The pickers on the form filter as you type (`checklist-filter.js`).

## Events

A fixed, code-defined set (`NotificationEventType`). Every event provides
`{event}`, `{timestamp}` (UTC ISO-8601) and `{details}`; machine events
also `{machine_name}` and `{machine_ip}`.

| Event | Fires when | Extra placeholders / `{details}` |
|---|---|---|
| `machine.unreachable` | a known-reachable machine stops answering | — |
| `machine.reachable_again` | it answers again | — |
| `machine.update_run.failed` | an update run fails | `{details}`: the run's error |
| `machine.update_run.succeeded` | an update run succeeds | `{details}`: its output |
| `machine.onboarded` | onboarding finishes | — |
| `machine.condition_matched` | all of a rule's conditions match (added automatically to rules with conditions) | `{rule_name}`, `{condition_summary}` |
| `machine.config_changed` | a facts refresh found tracked facts changed | `{changes}`, one line per change |
| `machine.security_updates` | new security updates are pending | `{package_count}`, `{packages}`, `{cves}` |
| `machine.reboot_required` | the machine newly needs a reboot | `{details}`: running kernel |
| `machine.smart_failed` | a disk's S.M.A.R.T. health turned FAILED | `{devices}` |
| `machine.service_failed` | systemd units entered the failed state | `{units}` |
| `machine.disk_full_predicted` | a filesystem is forecast full within 7 days | `{mount}`, `{days}` |
| `machine.zfs_pool_unhealthy` | a ZFS pool left ONLINE | `{pools}` |
| `machine.backup_failed` | a Proxmox VE backup, or a Backup Server job/task, newly failed | `{details}`: one line per failure |
| `machine.mail_queue_backlog` | a Mail Gateway queue reached 50 deferred/held | `{count}` |
| `machine.cluster_quorum_lost` | a Proxmox VE cluster lost quorum | `{cluster}`; `{details}`: offline nodes |
| `fleet_summary.generated` | the AI's scheduled fleet summary is ready | `{details}`: the report |
| `endpoint.down` | an endpoint check failed twice in a row | `{endpoint_name}`, `{endpoint_target}` |
| `endpoint.recovered` | it succeeds again after an announced outage | same |
| `endpoint.cert_expiring` | a certificate enters its warning window | also `{days}`, `{expires_at}` |

Health events (`app.services.health_events`) fire once on the transition
and never when the previous state is unknown, so upgrading debcontrol
doesn't page anyone about old problems.

**Adding an event**: add a member to the enum (no migration — stored as
JSON), call `app.services.notifications.notify(db, event, machine=…,
context=…)` right after the commit that makes it true, and add default
templates to `_DEFAULT_TEMPLATES` for **every** shipped locale.

## Conditions: thresholds instead of a fixed event

A rule can carry conditions such as "CPU over 90 %" or "/var over 85 %",
evaluated by a Beat sweep (Settings → Checks & retention → Notifications,
default 60 s). Fields come from a fixed registry
(`app.services.condition_fields.CONDITION_FIELDS`):

| Field | Type |
|---|---|
| `machine.os_id`, `.os_version`, `.kernel_version`, `.cpu_architecture` | string |
| `machine.cpu_cores`, `.uptime_seconds`, `.upgradable_count`, `.security_upgradable_count` | number |
| `machine.reboot_required`, `.is_reachable` | bool |
| `monitoring.cpu_percent`, `.load1/5/15`, `.ram_percent`, `.failed_services_count` | number |
| `monitoring.filesystem_use_percent` (needs a mount point) | number |
| `monitoring.max_temperature_c`, `.smart_failed_count` (bare metal) | number |
| `monitoring.disk_full_days` | number |
| `docker.unhealthy_count`, `.restarting_count`, `.image_updates_count`, `.exited_error_count` | number |

Operators: `gt gte lt lte eq ne` for numbers/booleans, plus `contains
not_contains in not_in` for strings. All conditions must match (AND; use
two rules for OR). A rule notifies on the false→true transition per
machine (`NotificationConditionState`), optionally only after the match
held for `sustained_seconds`. `monitoring.*` fields use the latest sample;
no sample = no match.

Thresholds (`gt`/`gte`) are drawn as dashed lines on the machine's
Monitoring charts.

### Rules as YAML

Conditions can be added row by row or pasted as YAML. A whole rule
exports and imports as YAML (`/notifications/rules/{id}/export`,
`/notifications/rules/export`, `/notifications/rules/import`), with
recipients, scope and template referenced by email/name. Import upserts
by `name`; YAML aliases are refused.

```yaml
name: High CPU on web servers
enabled: true
conditions:
  - field: monitoring.cpu_percent
    operator: gt
    value: "90"
    sustained_seconds: 300
recipients:
  users: [oncall@example.com]
  roles: [Operators]
scope:
  machine_groups: [Web]
template_name: High CPU alert
```

## Templates

Templates are plain text with `{placeholder}`s substituted by
`str.format_map` — no logic, no code; an unknown placeholder stays as
literal text.

- **Per event**: `/notifications/templates` shows each event's subject and
  body. The **built-in defaults are localized** — each recipient gets
  them in their own `User.locale` (English and Czech ship). An edited
  **override** is one text for everyone; *Reset to default* deletes it.
- **Custom templates**: named subject/body pairs a rule can pick in its
  Delivery section instead of the per-event text. Deleting one in use
  falls the rule back to the default.

## Delivery

Each rule picks one channel:

- **Email** — SMTP relay in Settings → Integrations (password encrypted;
  choosing the encryption fills in the usual port). One email per
  recipient, rendered in their language. With SMTP off, email rules are a
  silent no-op.
- **Webhook** — one JSON POST per rule: `{"event", "rule_name",
  "subject", "body", "machine_name", "machine_ip", "timestamp"}`. Put any
  secret in the URL itself (as Slack/Discord do). Only
  `notification.manage` accounts see the full URL; everywhere else —
  view-only accounts, the delivery history and error messages — it is
  shortened to `https://host/…` (`push_channels.redact_url`).
- **Push** (`app.services.push_channels`): one HTTPS request each.

| Channel | URL | Token (encrypted, write-only) | Recipient |
|---|---|---|---|
| ntfy | topic URL | access token, for protected topics | — |
| Gotify | server URL | application token | — |
| Telegram | — | bot token | chat id |
| Discord | webhook URL | — | — |
| Pushover | — | application token | user/group key |

Tokens are never shown again, never exported (an import may supply
`channel_token`; the API only reports `channel_token_set`) and masked out
of error text.

`notify()` finds every enabled rule for the event whose scope matches and
sends per rule (two rules matching the same person send two messages).
Failures are logged and recorded, never raised — a notification can't
break the job that triggered it. No retries.

## Delivery history and testing

Every attempt is a `NotificationLog` row (rule, event, channel, target,
`sent`/`failed`/`suppressed`, error, test flag). `/notifications/history`
shows the latest 200 (`?rule_id=` for one rule). Kept for
`notification_log_retention_days` (default 90).

**Send test** on a rule fires a sample through its channel and template —
email only to the admin clicking it, a webhook/push to its real target —
logged as a test.

## Maintenance windows

**Scheduling → Maintenance windows** (`/scheduling/maintenance`; old
`/notifications/maintenance` URLs redirect; `notification.view` /
`.manage`): a named time range (≤ 31 days) covering all machines, groups
and/or machines.

- While active, notifications **about covered machines** are withheld and
  recorded as **suppressed** with the window's name. Endpoint checks and
  the fleet summary are not muted.
- Condition rules that became true during the window don't re-announce
  afterwards; they fire again only after clearing and tripping again.
- **Pause scheduled tasks** (default on for new windows): scheduled tasks
  skip covered machines; manual actions are never blocked.
- *End now* ends it early; *Delete* removes it. Overview shows a banner.
- Audited as `maintenance_window.create`/`.update`/`.end`/`.delete`.

## Audit logging

Rule and template changes are audited (`notification_rule.create`/
`.update`/`.delete`/`.import`/`.test`, `notification_template.update`/
`.reset`, `notification_custom_template.create`/`.update`/`.delete`).
Individual sends are not — they're in the delivery history.

## REST API

`/api/v1/notifications/…` uses the same permissions, audit codes and
validation (`app.services.notification_rules`) as the web pages.

| Method & path | What it does |
|---|---|
| `GET /rules`, `GET /rules/{id}` | Rules in the YAML-export shape plus `id` (webhook URL shortened for view-only tokens) |
| `POST /rules` · `PUT /rules/{id}` · `DELETE /rules/{id}` | Create (409 on duplicate name) · replace · delete |
| `POST /rules/import` | Import a list, upsert by name, all or nothing |
| `POST /rules/{id}/test` | Send test (email to the token owner) |
| `GET /history?rule_id=&limit=&offset=` | Delivery history |
| `GET /templates` · `PUT/DELETE /templates/{event_type}` | Per-event templates · override · reset |
| `GET/POST /custom-templates` · `PUT/DELETE /custom-templates/{id}` | Custom templates |
| `GET/POST /maintenance-windows` · `PUT/DELETE /maintenance-windows/{id}` · `POST …/{id}/end` | Maintenance windows |
