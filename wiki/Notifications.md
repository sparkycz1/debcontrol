# 🔔 Notifications

*Rule-based alerts (email or webhook): which events to fire on, who to
notify, which machines to limit a rule to, and the templates/delivery
history behind it. Split out of [Architecture](Architecture.md) so this
one topic is easier to search — start there for the rest (auth/RBAC,
machine management, audit log, HTTP hardening).*

## What this is

`/notifications` (`app/web/routes/notifications.py`) lets an admin define
**rules**: "when event X happens, email these people, but only if it's
about one of these machines." A rule needs no code change — everything
here is data an admin manages from the UI. Gated by two permissions,
`notification.view` and `notification.manage`, deliberately separate from
`settings.manage` and `user.manage` — "who gets emailed about what" is a
narrower trust level than either of those.

Two sub-pages, one router:

- **`/notifications`** — the rules list, create/edit/delete a rule.
- **`/notifications/templates`** — one editable subject/body pair per
  event type (see "Templates" below).

Web-UI-only for now — see "REST API" at the bottom.

## Rules: event, recipients, scope

A `NotificationRule` (`app.db.models.notification_rule`) has:

| Field | Meaning |
|---|---|
| `name` / `description` | Admin-facing label, unique name. |
| `enabled` | A disabled rule is skipped entirely — kept, not deleted, so it's easy to switch back on. |
| `event_types` | Which events (see below) fire this rule — a rule can list more than one. |
| `users` | Directly-listed recipients. |
| `roles` | Every active account holding one of these `Role`s is also a recipient (see "Recipients by role" below) — no separate notification-only grouping concept. |
| `machines` / `machine_groups` | **Scope** — see below. |

**Recipients** are the union of `users` and every active user holding one
of the rule's `roles`, deduplicated by account. A recipient is silently
skipped (never an error, never blocks the others) if their account is
disabled or has no email address set (see "Who can receive an email"
below) — a rule with zero *reachable* recipients is simply a no-op for
that firing.

Both the user picker and the machine/machine-group pickers on the rule
form are filterable — a text box above each checkbox grid narrows it down
by name as you type (`checklist-filter.js`), so a fleet with hundreds of
machines or accounts stays usable rather than becoming a giant scroll.

**Scope** narrows *which machines* a rule cares about:

- **Empty `machines` and empty `machine_groups`** — the rule matches
  **every machine**, the same "no scope = everything" convention
  `MachineGroup`'s own "All machines" virtual group already uses.
- **Either list populated** — the rule fires only when the triggering
  event's machine is directly listed, or belongs to one of the listed
  machine groups.
- **An event with no machine at all** (today, only
  `FLEET_SUMMARY_GENERATED` — see below) always matches every rule's
  scope, since there's nothing to check it against.

## Who can receive an email

Any `User` with `email` set (**My account** → the user can set/change
their own; an admin can also set it from **Users** → edit) and whose
account is active. `User.email` is validated (`name@example.com` shape),
normalized lowercase, and unique — it is *not* used for login, only as
the notification address. An account with no email simply can't receive
a notification; nothing in the UI forces one to be set.

## Recipients by role

A rule can target a `Role` (`app.db.models.role`, the same one that
governs permissions — see [Authentication & RBAC](Authentication-RBAC.md))
directly, instead of only listing individual accounts: pick "Operators"
once and every account currently holding that role is a recipient, with
no separate list to keep in sync as people join, leave, or change job.
This deliberately reuses `Role` rather than a second, parallel
notification-only grouping concept — an earlier round of this feature had
exactly that (a standalone `UserGroup`), and it was folded into `Role`
once it became clear "who should hear about what" almost always tracks
"what job does this account do," which a role already answers.

A rule's actual recipient set is re-evaluated every time it fires, not
snapshotted when the rule was saved — promote someone into a targeted
role and they start receiving that rule's notifications on the very next
matching event, no rule edit needed.

## Events: what can trigger a rule

`NotificationEventType` (`app.db.models.notification_rule`) is a small,
fixed, code-defined set — **not** an open-ended "any audit action" hook.
Today:

| Event | Fires when | Machine-scoped? |
|---|---|---|
| `machine.unreachable` | A machine's reachability check finds it unreachable, **having previously been known reachable** — never on the very first check ever run for a machine (no prior state to transition *from*), and never on a tick that just confirms it's still unreachable. See `app.tasks.jobs._ping_all_machines` / `_check_machine_reachability_now`. | Yes |
| `machine.reachable_again` | The mirror image — a machine goes from known-unreachable back to reachable. | Yes |
| `machine.update_run.failed` | A triggered system-update run (`MachineUpdateRun`) finishes with `status=FAILED` — apt/flatpak/snap exited non-zero, or the machine couldn't be reached at all. See `app.tasks.jobs._run_machine_update`. | Yes |
| `machine.update_run.succeeded` | The same run finishes with `status=SUCCEEDED` instead — its own event type so a rule can opt into just failures, just successes, or both. | Yes |
| `machine.onboarded` | A machine finishes onboarding successfully (switches over to debcontrol's own SSH identity) — see `app.tasks.jobs._run_machine_onboarding`. | Yes |
| `fleet_summary.generated` | The AI assistant's scheduled fleet summary (Settings → AI Assistant → Scheduled fleet summary) finishes generating a new report. Frequency/provider/model stay configured there — only "who hears about it" lives here. See `app.tasks.ai_jobs._generate_fleet_summary`. | **No** — matches every rule regardless of machine/machine-group scope, since there's no single machine to check it against. |
| `machine.condition_matched` | A rule's own **conditions** (CPU/RAM/disk/facts thresholds — see "Condition-based rules" below) all match for a machine in scope. Added to a rule's `event_types` automatically whenever it has any conditions — never checked by hand. | Yes |

**Adding another event is a three-step recipe**, documented on
`NotificationEventType`'s own docstring in code:

1. Add a member to the `NotificationEventType` enum
   (`app/db/models/notification_rule.py`) — no migration needed, since
   a rule's `event_types` is stored as a plain JSON array of these
   string values, not a database enum type.
2. Call `app.services.notifications.notify(db, event_type, machine=...,
   context=...)` at the exact point the event happens, right after
   whatever it's reporting on is committed — see the call sites above for
   the pattern (only the ones that already fired an audit-log-style
   consequence, or that stand alone as a genuinely new fact, need this;
   don't call it from a routine polling tick that finds nothing changed).
3. Add its built-in default subject/body to `_DEFAULT_TEMPLATES` in
   `app/services/notifications.py` — **for every shipped locale** (see
   "Templates and locale" below), the same i18n-parity expectation the
   rest of the app has for user-facing strings.

## Condition-based rules: thresholds instead of a fixed event

Beyond the fixed lifecycle events above, a rule can carry one or more
**conditions** — "notify when CPU usage is over 90%," "notify when the
Debian version is X," "notify when /var is over 85% full." Evaluated by a
periodic Celery Beat sweep (`app.tasks.jobs.evaluate_notification_conditions`,
interval set in Settings → Checks & retention → Notifications, default 60s
— see [Development](Development.md)'s background-job recipe), not inline
with the events above.

**Field registry, not an arbitrary expression language.** A condition
references a field from a curated, code-defined set
(`app.services.condition_fields.CONDITION_FIELDS`) — everything the app
already tracks per machine, either from its latest facts snapshot
(`Machine`) or its latest monitoring sample (`MachineMonitoringSample`):

| Field key | Meaning | Value type |
|---|---|---|
| `machine.os_id` | Distro id (`debian`, `ubuntu`, ...) | string |
| `machine.os_version` | Full OS version string | string |
| `machine.kernel_version` | Kernel version | string |
| `machine.cpu_architecture` | e.g. `x86_64` | string |
| `machine.cpu_cores` | Core count | number |
| `machine.uptime_seconds` | Seconds since boot | number |
| `machine.reboot_required` | Pending-reboot flag | bool |
| `machine.upgradable_count` / `machine.security_upgradable_count` | Pending package updates | number |
| `machine.is_reachable` | Current reachability state | bool |
| `monitoring.cpu_percent` | Latest CPU sample | number |
| `monitoring.load1` / `.load5` / `.load15` | Latest load averages | number |
| `monitoring.ram_percent` | Computed from the latest sample's `ram_used_bytes`/`ram_total_bytes` | number |
| `monitoring.filesystem_use_percent` | One filesystem's usage — needs a **mount point** (e.g. `/var`) to disambiguate | number |
| `monitoring.failed_services_count` | Latest sample's failed-service count | number |

A `monitoring.*` field reads the machine's **latest**
`MachineMonitoringSample`; a machine with no sample yet simply never
matches (not an error). Operators: `gt`/`gte`/`lt`/`lte`/`eq`/`ne` for
numbers and booleans, plus `eq`/`ne`/`contains`/`not_contains`/`in`/
`not_in` for strings.

**Every condition in a rule must match — AND only.** For "or," create a
second rule; this keeps a rule's own meaning unambiguous and keeps the
YAML shape (below) simple enough to hand-edit, rather than building a
general boolean-expression parser for one feature.

**Debounce**: a rule notifies once on the true transition into "all
conditions match" for a given machine, and again after a false→true
cycle — never every sweep tick that just confirms "still matching," the
same spirit as `machine.unreachable`/`machine.reachable_again` above but
persisted (`NotificationConditionState`, one row per rule×machine) since
evaluation runs on its own sweep rather than inline with whatever wrote
the sample. A condition can optionally require the match to hold
continuously for `sustained_seconds` before it fires, to ignore a brief
spike.

**Configuring conditions — form or YAML, on the same rule.** The rule
form's **Trigger** section holds both the fixed-event checkboxes and
conditions together — a rule fires on either, so they live in one place
rather than two. A new rule starts with **no** condition rows; click
"+ Add condition" (`app/web/static/js/notification-conditions.js` clones a
blank row client-side — progressive enhancement only, nothing here is
required to submit the form) to add as many as needed, or use the "…or as
YAML" textarea below the rows to paste several at once — whichever is
filled in wins. Beyond that, a **whole rule** (name, description, events,
conditions, recipients-by-email/role-name, scope-by-machine-name/group-name,
template-by-name — see "Custom templates" below) can be exported and
re-imported as YAML — `GET /notifications/rules/{id}/export` (one) or
`GET /notifications/rules/export` (all), and `GET`/`POST
/notifications/rules/import` to paste one back in. Import **upserts by
`name`** (the same unique key the form already enforces) — re-importing
an unmodified export is a no-op, editing the YAML and re-importing updates
that rule in place. Example:

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

`template_name` is optional — omit it to use the per-event default/override
(see "Custom templates" below); when present, it must match an existing
`NotificationCustomTemplate.name` or the import fails with a clear error
rather than silently dropping it.

Same web-UI-only scope as the rest of this page — see "REST API" below.

## Placeholders: variables usable in a template

A template's subject and body are plain text with `{placeholder}`
markers, substituted via Python's `str.format_map` — **not** a template
engine (no loops, no conditionals, no code execution of any kind), so an
admin-edited body can never do anything beyond producing text. A
placeholder the current event doesn't provide, or a typo in one, is left
as **literal text** in the output (e.g. `{no_such_var}` prints exactly
that) rather than raising an error and losing the whole email.

Every event provides:

| Placeholder | Value |
|---|---|
| `{event}` | The event's code, e.g. `machine.unreachable` — same string as `NotificationEventType.value`. |
| `{timestamp}` | UTC time the event fired, ISO-8601 (e.g. `2026-09-11T21:00:00+00:00`). |
| `{details}` | Free-form, event-specific text — see the table below for what each event puts here. |

Machine-scoped events (everything except `fleet_summary.generated`)
additionally provide:

| Placeholder | Value |
|---|---|
| `{machine_name}` | The machine's display name. |
| `{machine_ip}` | The machine's configured IP address/hostname. |

What `{details}` actually contains, per event:

| Event | `{details}` |
|---|---|
| `machine.unreachable` / `machine.reachable_again` | Empty — the subject/body wording alone already says what happened. |
| `machine.update_run.failed` | The run's recorded error message (apt's exit status, or the connection failure) — `MachineUpdateRun.error`. |
| `machine.update_run.succeeded` | The run's captured output. |
| `machine.onboarded` | Empty — the subject/body wording alone already says what happened. |
| `fleet_summary.generated` | The full generated report text (the same content shown on the Dashboard). |
| `machine.condition_matched` | Also provides `{rule_name}` and `{condition_summary}` (a human-readable rendering of the matched conditions, e.g. "cpu_percent gt 90"); `{details}` is empty. |

## Templates: one subject/body pair per event, per your language

`/notifications/templates` lists every `NotificationEventType` with its
current subject (and whether it's the built-in default or a customized
override) and a link to edit it. Editing writes a `NotificationTemplate`
row (`event_type` unique, `subject`, `body`); deleting it via **Reset to
default** removes the row — there's no separate "undo," the absence of a
row *is* "use the built-in default."

**An override is a single value, not per-language** — if you customize
`machine.unreachable`'s wording, every recipient gets that exact text
regardless of their own UI language. The **built-in defaults**, by
contrast, *are* localized: each recipient's email is rendered using
**their own** `User.locale` (the same per-account language setting used
everywhere else in the app — see [Authentication & RBAC → Per-user UI
language](Authentication-RBAC.md#per-user-ui-language-i18n)), falling
back to English for a locale with no translation. This is also why the
Templates page itself shows the default text in *your own* UI language
when you're looking at (not yet overriding) an event's template — it's
previewing exactly what an English- or Czech-language recipient would
actually receive.

Shipped locales for the built-in defaults today: English and Czech
(`app.services.notifications._DEFAULT_TEMPLATES`) — the same two locales
`app/i18n/locales/` ships for the rest of the UI.

### Custom templates: a named template any rule can pick

Beyond the one-per-event default/override above, `/notifications/templates`
also lists **custom templates** (`NotificationCustomTemplate`: `name`
unique, `subject`, `body` — same plain-text `{placeholder}` substitution,
no localization of its own since it's one admin-written value regardless
of recipient) — "Add template" there creates one. A rule's **Delivery**
section has an "Email template" picker: leave it on "— default for event —"
to keep using the per-event default/override exactly as before, or pick a
custom template to use its subject/body instead, for that rule alone,
regardless of which event actually fired. Deleting a custom template that's
in use just falls the referencing rule(s) back to their per-event default
— never blocked, never leaves a rule broken.

## Delivery: email (SMTP) or webhook, per rule

Each rule picks a **delivery channel** (`NotificationRule.delivery_channel`,
its Delivery section): **email** (the default — recipients/roles below
apply) or **webhook** (`webhook_url` — a plain JSON POST, recipients/roles
are ignored entirely, only scope still narrows which machines fire it).

**Email.** Settings → Integrations has the SMTP relay section
(`AppSettings.smtp_*` — host/port/encryption/username/password/from
address/from name), same encrypted-secret convention as LDAP/OIDC next to
it. Switching the **Encryption** dropdown there fills in the conventional
port for that choice (25 for none, 587 for STARTTLS, 465 for SSL/TLS) —
still a plain, editable number field, so a nonstandard port stays
possible. `smtp_enabled` gates only the email channel: with it off, or no
host set, an email rule's dispatch is a complete, silent no-op — a webhook
rule on the same event still fires.

**Webhook.** One JSON POST per matching rule (not per recipient — a
webhook has no concept of "recipients"): `{"event", "rule_name",
"subject", "body", "machine_name", "machine_ip", "timestamp"}`. No
signature/bearer-auth scheme of its own — embed a token or secret path
segment in `webhook_url` itself (the way a Slack or Discord incoming
webhook link already works), since that URL is admin-authored config
requiring `notification.manage`, not untrusted input.

`app.services.notifications.notify(db, event_type, *, machine=None,
context=None)` is the one function that turns a fired event into an
actual send:

1. Find every **enabled** rule listing this event type whose scope
   includes `machine` (or has no scope at all).
2. For **each matching rule** (not once for the union of every rule's
   recipients — see below):
   - **Webhook rule**: POST once to its `webhook_url`, using its own
     `custom_template` (or the per-event default) for the `subject`/`body`
     fields in the payload.
   - **Email rule**: skip it if SMTP isn't enabled/configured; otherwise
     resolve its own recipients (deduplicated, email-having, active
     accounts only) and, for each, render the subject/body — its own
     `custom_template` if set, else the per-event admin override, else the
     built-in default in *that recipient's* locale — and send one
     individual email via stdlib `smtplib`, run through `asyncio.to_thread`
     (the same sync-library/async-caller seam every Celery task in
     `app.tasks.jobs` already crosses).

**Rendered per rule, not deduplicated across every matching rule.** Since a
rule can select its own template, two rules that both match the same
event for the same person are two legitimately different emails to send,
not one to collapse — so a recipient targeted by more than one rule for
the same event now gets one email per rule, each in that rule's own
wording. A fleet with the common "one rule per event" setup sees no change
at all; this only affects a deliberately overlapping setup.

**Every failure here is caught and logged, never raised** — no SMTP
configured, no matching rule, no recipient with an email, the SMTP server
or webhook endpoint itself refusing the connection, a single recipient's
send failing while others succeed. A notification that fails to send must
never be able to break the background job that triggered it, the same
"best-effort, never load-bearing" spirit `app.audit_syslog.forward_to_syslog`
already has for the audit log's own external mirror. There is no retry
and no delivery queue — a failed send is logged and recorded (see
"Delivery history" below) and moved past.

One connection is opened per recipient rather than one shared connection
for a multi-recipient email send — simple and correct at the small
recipient counts a notification rule realistically has; reusing a
connection is a possible future optimization, not a correctness concern
today.

## Delivery history and testing

Every send *attempt* — real or "Send test" — is recorded to
`NotificationLog` (`app.db.models.notification_log`): rule, event, channel,
target (recipient email or webhook URL), status (`sent`/`failed`, with the
error for a failure), and whether it was a test. `/notifications/history`
lists the last 200, newest first — for "did that alert actually go out"
troubleshooting that the audit log (which only records rule
create/edit/delete, not individual sends) doesn't cover. Add `?rule_id=`
(a "View delivery history for this rule" link on that rule's own edit page)
to narrow it to one rule's attempts — `NotificationLog.rule_id` carries its
own index specifically for this filter. Purged on its own schedule
(`AppSettings.notification_log_retention_days`, Settings → Checks &
retention → Notifications, default 90 days — `app.tasks.jobs.
purge_old_notification_logs`).

**"Send test"** on a rule's edit page (`app.services.notifications.
send_test_notification`) fires one synthetic notification through that
rule's own configured channel/template, bypassing its real
recipients/scope entirely: email goes only to the admin clicking the
button (never the rule's actual audience), a webhook rule still POSTs to
its real `webhook_url`. Lets an admin verify SMTP/webhook config and
template wording actually work without waiting for a real alert. Logged
with `is_test=True` so it's clearly distinguishable in the history list.

## Condition thresholds on the Monitoring tab

A machine's Monitoring tab charts (CPU, RAM, per-filesystem-mount usage —
`machines/monitoring.html`) draw a dashed reference line at the lowest
matching `gt`/`gte` condition threshold configured for that machine
(`app.services.notifications.condition_thresholds_for_machine`), so "where
would this actually alert" is visible directly on the trend, not just as a
number on the Notifications page. The RAM chart's line additionally shows
the absolute value (e.g. "Alert ≥ 90% (3.6 GB)") using that machine's
latest known total RAM, since a bare percentage doesn't say what the
actual ceiling is. Best-effort and visual only — `lt`/`lte`/`eq`/other
operators aren't representable as a ceiling line and are simply not drawn;
this never affects whether the condition itself fires.

## Audit logging

Rule/template create-edit-delete are all audit-logged
(`notification_rule.create`/`.update`/`.delete`/`.import`/`.test`,
`notification_template.update`/`.reset`,
`notification_custom_template.create`/`.update`/`.delete`) — the same
"every mutation gets an entry" convention every other admin-config page
follows. **Actually sending a notification is not itself audit-logged**
— it's a downstream *consequence* of an event that (where relevant)
already has its own audit entry, not a new auditable action of its own;
logging every individual send here would flood the trail with what's
really the same fact repeated per recipient. That per-send record lives
in `NotificationLog` instead — see "Delivery history" above, a
troubleshooting log, not an audit trail.

## REST API

Deliberately web-UI-only this round (see `api_v1.py`'s module docstring)
— rules and templates are only reachable through the web UI today. This
is new-and-not-yet-extended, not a permanent policy decision
the way SSH key rotation or LDAP/OIDC config are: a REST equivalent is a
reasonable, expected follow-up once there's a concrete need for it.
