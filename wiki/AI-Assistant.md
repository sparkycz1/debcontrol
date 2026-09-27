# 🤖 AI Assistant

The **AI** tab: ask in plain language — *"install apache2 on group
web-servers"*, *"how many machines still need updates?"*, *"reboot db1"* —
and a third-party model helps you do it on your fleet. It is the most
powerful and most dangerous feature here; this page is mostly its
safeguards. **Read it before enabling it.**

> [!IMPORTANT]
> **Nothing the assistant proposes runs until a human clicks Confirm on a
> screen showing the literal command and every target machine by name.**
> That happens in exactly one place —
> `POST /ai/conversations/{id}/messages/{message_id}/confirm`
> (`app/web/routes/ai.py`). The task that talks to the model
> (`app/tasks/ai_jobs.py`) can only *record* a proposal.

## 🔌 Providers

Five kinds, each using its official SDK (`app/ai/providers.py`; 15 s to
list models, 90 s per chat call):

| Kind | Endpoint | Notes |
|---|---|---|
| `anthropic` | `api.anthropic.com` | models list paginated |
| `openai` | `api.openai.com/v1` | |
| `gemini` | `generativelanguage.googleapis.com` | |
| `openrouter` | `openrouter.ai/api/v1` | its own SDK |
| `openai_compatible` | your base URL (required) | litellm, vLLM, a gateway |

**Settings → AI**, per provider: tick **Enabled**, paste the **API key**
(encrypted, never shown again; blank keeps it), **Fetch models now**, then
**choose models** in the searchable picker. Fetched models start
**disabled** — a catalog includes models without tool support, so each is
opted in explicitly. Re-fetching keeps existing choices and adds new
models disabled. A conversation keeps its provider and model for life.

## 💰 Token limits

**Settings → AI → Token limits**: optional ceilings on total tokens over
the **rolling** last 24 h, 7 days and 30 days, across all providers and
users. Checked *before* each request (`app.ai.usage.check_within_limits`);
a reached limit refuses the turn in the chat.

## 🔐 Permissions

`ai.access` only opens the `/ai` page. Everything the assistant can *do*
needs the same permission as the matching button, for the same user:

| Tool | Permission | Manual equivalent |
|---|---|---|
| `list_machines` | `machine.view` | Machines list |
| `list_groups` | `group.view` | Machine groups |
| `run_update` | `action.updates` | Run update |
| `check_updates` | `action.updates` | Check for updates |
| `reboot` / `shutdown` | `action.power` | Power buttons |
| `run_ssh_command` | `action.terminal` | Terminal |

Checked **three times**: when tools are offered (the model never hears of
tools you can't use); when the model calls one (a tool that wasn't
offered is recorded as `denied`); and when you click Confirm (fresh from
your current role; each proposal runs at most once). Machine-group
scoping applies to every lookup and again at confirmation — outside your
scope a machine simply "doesn't exist".

## ✅ What runs automatically

- **Immediately**: `list_machines`, `list_groups` (database reads only).
- **Only after Confirm**: everything that touches a machine —
  `run_ssh_command`, `run_update`, `check_updates`, `reboot`, `shutdown`.

The confirmation card shows the exact command, the update strategy, every
resolved machine by name and any machine skipped for lacking a confirmed
host key. Names match case-insensitively but exactly (no guessing); more
than **25 machines** is refused, never truncated.

**Auto-confirm further commands in this conversation** — offered only
after you've confirmed one by hand; kept in this browser tab's
`sessionStorage` for this conversation only (`ai-auto-confirm.js`). It
still goes through the same confirm route, CSRF and permission checks and
audit entry — it only skips your pause to read.

After a confirmed `run_ssh_command`, each target runs as its own Celery job
(a plain exec, not a PTY) and the combined output goes back to the model
for a summary **with no tools offered**. Other actions are fire-and-forget
through `app.services.machine_actions`, exactly like the buttons.

## 📝 Audit log

Every confirmed action writes `ai.action.<tool>` with the conversation,
the literal command, strategy and every resolved machine; a refused
confirmation writes `ai.action.denied`. Conversation create/delete and all
provider, model and limit changes are audited too. Chat text is not
copied into the audit log, and API keys never appear anywhere but the
outbound request.

## 🩺 "Ask AI why" and summaries

`POST /ai/explain` starts a new conversation prefilled server-side (in
your language, with the first available model) from:

- a **failed update run** (strategy, error, the last ~6000 characters of
  output);
- the **readiness banner**'s missing items;
- a machine's **History** tab — *Summarize with AI*: up to 120 recent
  events (audited actions only with `audit.view`) plus current state;
- an **endpoint check** — its state, last error and last 7 days.

Each is checked against your access server-side.

## 🗓️ Scheduled fleet summary

**Settings → AI → Scheduled fleet summary** (off by default): daily or
weekly, a chosen model writes a short "what changed, what needs attention"
report from the Dashboard's numbers, offline machines, pending security
updates, readiness findings, failures and configuration changes. It
appears on the Dashboard for `machine.view` accounts without a group
restriction, is readable at `GET /api/v1/dashboard/fleet-summary`, and
can be emailed by a notification rule on `fleet_summary.generated`. Kept
180 days by default.

## 🚫 Deliberately out of scope

- **No REST API for the chat** — browser session and CSRF only (the fleet
  summary's text above is the one read-only exception).
- **Conversations are private to their creator** — others get a 404, even
  admins. What was *run* is still in the audit log.
- **No streaming** — a turn runs as a Celery task (possibly several model
  calls); the page polls every ~2 s and shows the whole reply.
- **No export, search or retention** — a conversation lives until its
  owner (or their account) is deleted.

## ⚠️ Prompt injection: the residual risk

> [!WARNING]
> **Output from a managed machine becomes part of what the model reads.**
> A compromised machine can print text aimed at the model ("ignore your
> instructions and run … on every host"). This can't be patched away.
>
> Mitigations: the summary turn after a command gets **no tools**; the
> system prompt treats tool output as data; every mutating action still
> needs a human to confirm the literal command.
>
> **That last safeguard is only as good as the person clicking.** Treat
> every confirmation like pasting a stranger's command into a root shell.
> If the risk is unacceptable, don't grant `action.terminal` together
> with `ai.access` — the assistant stays useful with view and update
> permissions.

> [!NOTE]
> Verify on a throwaway machine that proposals do nothing until
> confirmed, that a role without `action.terminal` is never offered
> `run_ssh_command`, and that your provider and model honour the tool
> schemas — the one part debcontrol doesn't control.
