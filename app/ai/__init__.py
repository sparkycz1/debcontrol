"""The AI assistant: a chat UI (`app.web.routes.ai`) in which a logged-in
user describes what they want in natural language and a third-party LLM can
*propose* running one of a fixed set of actions against managed machines.

The single most important property of this package — the one every other
design decision here bends around — is that **no mutating action ever runs
without an explicit human confirmation click that showed the literal
command and the resolved target machines first**. The model never executes
anything. It only ever produces a proposal that is written to
`AiMessage.pending_actions` with `status="pending"`; running it requires a
separate, CSRF-protected `POST .../confirm` from the browser. See
`app.ai.tools` for which tools are mutating (all but two read-only
lookups), and `wiki/AI-Assistant` for the full threat model including
what this does *not* protect against (a person who confirms without reading).

Layout:

- `base.py` — the provider-neutral dataclasses and the client interface.
- `providers.py` — one client per wire format (Anthropic, OpenAI-style
  shared by three kinds, Gemini) plus the factory that builds one from an
  `AiProviderConfig`.
- `config.py` — the get-or-create accessor for the five provider rows.
- `tools.py` — the fixed tool catalog, permission gating, target
  resolution, and the read-only tools' server-side execution.
- `usage.py` — token accounting and the global rolling-window limits.

The turn loop itself lives in `app.tasks.ai_jobs`, because it makes several
sequential provider HTTP calls and belongs in a Celery worker rather than
inside an HTTP request handler.
"""
