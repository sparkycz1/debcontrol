# 🔔 Notifications

*Rule-based email alerts: which events to fire on, who to notify, which
machines to limit a rule to, and the SMTP relay + templates behind
delivery. Split out of [Architecture](Architecture.md) so this one topic
is easier to search — start there for the rest (auth/RBAC, machine
management, audit log, HTTP hardening).*

## What this is

`/notifications` (`app/web/routes/notifications.py`) lets an admin define
**rules**: "when event X happens, email these people, but only if it's
about one of these machines." A rule needs no code change — everything
here is data an admin manages from the UI. Gated by two permissions,
`notification.view` and `notification.manage`, deliberately separate from
`settings.manage` and `user.manage` — "who gets emailed about what" is a
narrower trust level than either of those.

Three sub-pages, one router:

- **`/notifications`** — the rules list, create/edit/delete a rule.
- **`/notifications/groups`** — **user groups**, a reusable "notify all of
  these people" recipient list (see below).
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
| `user_groups` | Recipient groups (see "User groups" below) — every active member with an email gets notified. |
| `machines` / `machine_groups` | **Scope** — see below. |

**Recipients** are the union of `users` and every member of every group in
`user_groups`, deduplicated by account. A recipient is silently skipped
(never an error, never blocks the others) if their account is disabled or
has no email address set (see "Who can receive an email" below) — a rule
with zero *reachable* recipients is simply a no-op for that firing.

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

## User groups: a reusable recipient list

`/notifications/groups` manages `UserGroup` — a plain named group of
accounts (`app.db.models.user_group`) that exists **purely** to be a
notification target. It is deliberately unrelated to two other things
that sound similar:

- **`Role`** (`app.db.models.role`) answers "what may this account *do*"
  (permissions) — nothing to do with who gets emailed.
- **`MachineGroup`** groups *machines*, not people.

A user can belong to any number of `UserGroup`s (unlike a machine, which
has exactly one `MachineGroup` or none). Creating/editing a group just
picks which user accounts are members; membership has no other effect
anywhere else in the app.

## Events: what can trigger a rule

`NotificationEventType` (`app.db.models.notification_rule`) is a small,
fixed, code-defined set — **not** an open-ended "any audit action" hook.
Today:

| Event | Fires when | Machine-scoped? |
|---|---|---|
| `machine.unreachable` | A machine's reachability check finds it unreachable, **having previously been known reachable** — never on the very first check ever run for a machine (no prior state to transition *from*), and never on a tick that just confirms it's still unreachable. See `app.tasks.jobs._ping_all_machines` / `_check_machine_reachability_now`. | Yes |
| `machine.reachable_again` | The mirror image — a machine goes from known-unreachable back to reachable. | Yes |
| `machine.update_run.failed` | A triggered system-update run (`MachineUpdateRun`) finishes with `status=FAILED` — apt/flatpak/snap exited non-zero, or the machine couldn't be reached at all. See `app.tasks.jobs._run_machine_update`. | Yes |
| `fleet_summary.generated` | The AI assistant's scheduled fleet summary (Settings → AI Assistant → Scheduled fleet summary) finishes generating a new report. Frequency/provider/model stay configured there — only "who hears about it" lives here. See `app.tasks.ai_jobs._generate_fleet_summary`. | **No** — matches every rule regardless of machine/machine-group scope, since there's no single machine to check it against. |

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
| `fleet_summary.generated` | The full generated report text (the same content shown on the Dashboard). |

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

## Delivery: SMTP, one email per recipient

Settings → Integrations has the SMTP relay section (`AppSettings.smtp_*`
— host/port/encryption/username/password/from address/from name), same
encrypted-secret convention as LDAP/OIDC next to it. Switching the
**Encryption** dropdown there fills in the conventional port for that
choice (25 for none, 587 for STARTTLS, 465 for SSL/TLS) — still a plain,
editable number field, so a nonstandard port stays possible.
`smtp_enabled` gates everything below it: with it off, or no host set,
notification dispatch is a complete, silent no-op — nothing is queued or
retried, it simply doesn't try.

`app.services.notifications.notify(db, event_type, *, machine=None,
context=None)` is the one function that turns a fired event into sent
email:

1. Bail out immediately if SMTP isn't enabled/configured.
2. Find every **enabled** rule listing this event type whose scope
   includes `machine` (or has no scope at all).
3. Resolve those rules' recipients (deduplicated, email-having, active
   accounts only).
4. For each recipient, render the subject/body — admin override if one
   exists, otherwise the built-in default in *that recipient's* locale —
   and send **one individual email** via stdlib `smtplib` (STARTTLS/
   SSL-TLS/none, matching the configured encryption), run through
   `asyncio.to_thread` (the same sync-library/async-caller seam every
   Celery task in `app.tasks.jobs` already crosses — no new SMTP client
   dependency for this one feature).

**Every failure here is caught and logged, never raised** — no SMTP
configured, no matching rule, no recipient with an email, the SMTP server
itself refusing the connection, a single recipient's send failing while
others succeed. A notification that fails to send must never be able to
break the background job that triggered it, the same "best-effort, never
load-bearing" spirit `app.audit_syslog.forward_to_syslog` already has for
the audit log's own external mirror. There is no retry and no delivery
queue — a failed send is simply logged (`app.services.notifications`'s
own logger) and moved past.

One connection is opened per recipient rather than one shared connection
for a multi-recipient send — simple and correct at the small recipient
counts a notification rule realistically has; reusing a connection is a
possible future optimization, not a correctness concern today.

## Audit logging

Rule/group/template create-edit-delete are all audit-logged
(`notification_rule.create`/`.update`/`.delete`,
`user_group.create`/`.update`/`.delete`,
`notification_template.update`/`.reset`) — the same "every mutation gets
an entry" convention every other admin-config page follows. **Actually
sending a notification email is not itself audit-logged** — it's a
downstream *consequence* of an event that (where relevant) already has
its own audit entry, not a new auditable action of its own; logging every
individual email send would flood the trail with what's really the same
fact repeated per recipient.

## REST API

Deliberately web-UI-only this round (see `api_v1.py`'s module docstring)
— rules, groups, and templates are only reachable through the web UI
today. This is new-and-not-yet-extended, not a permanent policy decision
the way SSH key rotation or LDAP/OIDC config are: a REST equivalent is a
reasonable, expected follow-up once there's a concrete need for it.
