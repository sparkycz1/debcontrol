## Summary

<!-- What does this change, and why? A bullet list is fine. -->

-

## Test plan

<!-- How did you verify this? Check what applies, add anything specific
     to this change (a screenshot, a manual repro of a bug you fixed, ...). -->

- [ ] `uv run ruff check .`
- [ ] `uv run mypy app alembic tests`
- [ ] `uv run pytest`
- [ ] `uv run alembic heads` (only if this changes a model/migration — must show exactly one head)
- [ ] Added/updated a test covering this change
