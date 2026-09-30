"""Fuzz targets for the code that parses input debcontrol doesn't control:
command output from managed machines, network replies, and what a user types
or imports. `fuzz.targets` holds the targets (plain Python, also run by
`tests/test_fuzz_targets.py`); `fuzz.run` drives one of them with Atheris
(coverage-guided, Linux only — see `.github/workflows/fuzz.yml`)."""

import os

# The app's settings are validated on import and refuse to load without
# these. Dummy values only — a fuzz run never touches a database or Redis.
for _name, _value in {
    "SECRET_KEY": "fuzz-only-secret-key-not-for-real-use-000000",
    "ENCRYPTION_KEY": "IYH8EiMlmjkDacPXmvWQgDjTojLMD6GDwD8STyL1x0Y=",
    "DATABASE_URL": "postgresql+asyncpg://fuzz:fuzz@localhost/fuzz",
    "REDIS_URL": "redis://localhost:6379/0",
    "POSTGRES_PASSWORD": "fuzz",
    "REDIS_PASSWORD": "fuzz",
    "INFORM_TOKEN": "fuzz-only-inform-token-not-for-real-use-000000",
}.items():
    os.environ.setdefault(_name, _value)
