# Contributing

Thanks for taking the time to contribute. This file covers the basics;
day-to-day development conventions (running the test/lint/type-check
gate, adding a database migration, project layout, ...) live in the wiki
so they don't drift out of sync in two places:

- **[wiki/Development](https://github.com/sparkycz1/debcontrol/wiki/Development)** — setup, running the gate, adding a migration, and more.
- **[CLAUDE.md](CLAUDE.md)** — the architecture and the checklist every change is expected to go through (REST API parity, wiki and i18n parity, upgrade safety, security, scale).

Everyone participating is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

For anything beyond a small, obvious fix, **open an issue first** — use
the [bug report](.github/ISSUE_TEMPLATE/bug_report.md) or
[feature request](.github/ISSUE_TEMPLATE/feature_request.md) template.
Several product decisions here are deliberate and already settled (see
[wiki/Home](https://github.com/sparkycz1/debcontrol/wiki/Home)) —
opening an issue first avoids spending time on a PR that goes against
one of those.

**Security vulnerability?** Don't open a public issue — see
[SECURITY.md](.github/SECURITY.md) instead.

## Making a change

1. Fork the repository (or create a branch, if you have push access) and
   make your change.
2. Run the full gate before opening a PR:
   ```bash
   uv sync
   uv run ruff check .
   uv run mypy app alembic tests
   uv run pytest
   uv run alembic heads   # must show exactly one head
   ```
3. Open a pull request. The [PR template](.github/pull_request_template.md)
   is prefilled — fill in a summary and how you tested it. CI runs the
   same gate automatically.

`main` is protected — every change, including from maintainers, goes
through a pull request and has to pass CI before it can merge.

## License

This project is licensed under
[PolyForm Noncommercial 1.0.0](LICENSE). By submitting a contribution,
you agree it's provided under that same license.
