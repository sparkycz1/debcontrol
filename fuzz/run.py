"""Runs one target from `fuzz.targets` under Atheris, coverage-guided:

    uv sync --group fuzz          # Linux only — Atheris has no other wheels
    uv run python -m fuzz.run <target> -max_total_time=60

Anything after the target name goes to libFuzzer (`-max_total_time`,
`-runs`, a corpus directory, ...). A crash leaves a `crash-<sha1>` file with
the input that caused it; replay it with `python -m fuzz.run <target>
crash-<sha1>`, then add it to `tests/test_fuzz_targets.py`'s seeds once
fixed. `.github/workflows/fuzz.yml` runs every target on each PR and weekly.
"""

import sys

import atheris

# Instrument only this project's own code — coverage feedback from inside
# FastAPI, SQLAlchemy or PyYAML isn't what these targets are hunting.
with atheris.instrument_imports(include=["app"]):
    from fuzz.targets import TARGETS


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in TARGETS:
        names = ", ".join(TARGETS)
        sys.exit(f"usage: python -m fuzz.run <target> [libFuzzer flags]\ntargets: {names}")
    target = TARGETS[sys.argv[1]]
    atheris.Setup([sys.argv[0], *sys.argv[2:]], target)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
