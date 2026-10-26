"""The Postgres that CI's `postgres` job tests against is the one a
deployment runs. Dependabot bumps the image in docker-compose.yml, but not
a service container inside a workflow — this catches the two drifting."""

from __future__ import annotations

from pathlib import Path

import yaml

_ROOT = Path(__file__).parent.parent


def test_ci_postgres_matches_docker_compose() -> None:
    compose = yaml.safe_load((_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    ci = yaml.safe_load((_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    deployed = compose["services"]["db"]["image"]
    tested = ci["jobs"]["postgres"]["services"]["postgres"]["image"]
    assert tested == deployed
