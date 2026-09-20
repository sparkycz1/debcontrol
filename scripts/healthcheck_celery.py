#!/usr/bin/env python3
"""Liveness check for the `worker`/`beat` Celery containers, run as each
service's own `docker-compose.yml` HEALTHCHECK.

Both services build from the same image as `web` and otherwise inherit its
Dockerfile-level HEALTHCHECK, which curls `web`'s own :8080/healthz — a
port neither `worker` nor `beat` ever listens on, so both always reported
"unhealthy" regardless of whether Celery itself was actually fine.

Looks for a process whose own command line contains the given role
("worker" or "beat") by reading /proc directly — no extra package needed.
Deliberately not a broker-RPC check (`celery inspect ping`), so a slow or
congested broker can't make this flap on its own; this only asks "is the
expected process still running", the same thing a Dockerfile HEALTHCHECK
is meant to answer.

Excludes this checking process's own pid and its parent — this script's
own command line necessarily contains the search string too (e.g. `python
scripts/healthcheck_celery.py worker` run as the "worker" role's own
check), so without excluding self+parent this would always match
vacuously regardless of whether the real target process exists.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _cmdline(pid: str) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.decode("utf-8", errors="replace").replace("\x00", " ")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: healthcheck_celery.py <role>", file=sys.stderr)
        return 2
    role = argv[1]

    excluded = {str(os.getpid()), str(os.getppid())}
    for entry in Path("/proc").iterdir():
        pid = entry.name
        if not pid.isdigit() or pid in excluded:
            continue
        if role in _cmdline(pid):
            return 0

    print(f"no process with {role!r} in its command line found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
