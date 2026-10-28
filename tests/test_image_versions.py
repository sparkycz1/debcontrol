"""Which newer version of a container image exists
(`app.services.image_versions`): newer tags from the image's public
registry, and the version the image declares about itself."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx2

from app.db.models.machine import Machine
from app.services import image_versions
from app.ssh.image_updates import parse_image_update_output, parse_image_versions
from app.tasks import jobs
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token


def test_image_references_are_read_like_docker_reads_them() -> None:
    parse = image_versions.parse_image

    assert parse("nginx") == image_versions.ImageRef("docker.io", "library/nginx", "latest")
    assert parse("nginx:1.27.1").tag == "1.27.1"  # type: ignore[union-attr]
    assert parse("grafana/grafana:11.2.0") == image_versions.ImageRef(
        "docker.io", "grafana/grafana", "11.2.0"
    )
    assert parse("ghcr.io/home-assistant/home-assistant:2026.9.1") == image_versions.ImageRef(
        "ghcr.io", "home-assistant/home-assistant", "2026.9.1"
    )
    assert parse("lscr.io/linuxserver/sonarr:4.0.9").registry == "ghcr.io"  # type: ignore[union-attr]
    assert parse("registry.lan:5000/team/app:1.2").registry == "registry.lan:5000"  # type: ignore[union-attr]
    assert parse("nginx@sha256:" + "a" * 64) is None
    assert parse("Bad Name:1") is None and parse("") is None


def test_newer_tags_keep_the_shape_of_the_running_one() -> None:
    tags = ["1.27.0", "1.27.1", "1.27.3", "1.27.3-alpine", "1.28", "1.29.0", "v1.30.0", "latest"]

    assert image_versions.newer_tags("1.27.1", tags) == {"series": "1.27.3", "newest": "1.29.0"}
    # The flavour and the "v" are part of the shape.
    assert image_versions.newer_tags("1.27.1-alpine", tags) == {"series": "1.27.3-alpine"}
    assert image_versions.newer_tags("v1.29.0", tags) == {"newest": "v1.30.0"}
    # Numbers compare as numbers, and a one-part tag has no series.
    assert image_versions.newer_tags("9", ["10", "8", "9"]) == {"newest": "10"}
    assert image_versions.newer_tags("1.29.0", tags) == {}
    assert image_versions.newer_tags("latest", tags) == {}
    assert image_versions.newer_tags("stable-slim", tags) == {}


def test_declared_versions_come_with_the_machine_output() -> None:
    raw = (
        "nginx:1.27.1\tsha256:new\tnginx@sha256:old\t1.27.1\t1.27.1\n"
        "app:latest\tsha256:new\tapp@sha256:old\t2.3.0\t2.4.1\n"
        "plain:1\tsha256:same\tplain@sha256:same\t<no value>\t\n"
        "old-format:1\tsha256:x\told-format@sha256:x\n"
    )

    assert parse_image_update_output(raw) == {
        "nginx:1.27.1": "update",
        "app:latest": "update",
        "plain:1": "current",
        "old-format:1": "current",
    }
    assert parse_image_versions(raw) == {
        "nginx:1.27.1": {"local_version": "1.27.1", "remote_version": "1.27.1"},
        "app:latest": {"local_version": "2.3.0", "remote_version": "2.4.1"},
    }


def _registry(requests: list[str]) -> httpx2.MockTransport:
    def handle(request: httpx2.Request) -> httpx2.Response:
        requests.append(f"{request.url.host}{request.url.path}")
        if request.url.path.endswith("/token"):
            return httpx2.Response(200, json={"token": "anonymous"})
        if request.url.path == "/v2/library/nginx/tags/list":
            assert request.headers["authorization"] == "Bearer anonymous"
            return httpx2.Response(200, json={"tags": ["1.27.1", "1.27.3", "1.29.0"]})
        return httpx2.Response(404, json={})

    return httpx2.MockTransport(handle)


async def test_only_public_registries_are_asked_and_each_repository_once() -> None:
    requests: list[str] = []

    found = await image_versions.describe(
        {
            "nginx:1.27.1": {},
            "nginx:1.27.3": {},
            "registry.lan:5000/team/app:1.2.0": {},
            "app:latest": {"local_version": "2.3.0", "remote_version": "2.4.1"},
            "ghcr.io/nobody/missing:1.0.0": {},
        },
        transport=_registry(requests),
    )

    assert found == {
        "nginx:1.27.1": {
            "series": "1.27.3",
            "newest": "1.29.0",
            # The newest tag each limited update policy allows.
            "allowed": {"minor": "1.29.0", "patch": "1.27.3"},
        },
        "nginx:1.27.3": {"newest": "1.29.0", "allowed": {"minor": "1.29.0"}},
        "app:latest": {"local_version": "2.3.0", "remote_version": "2.4.1"},
    }
    assert not any("registry.lan" in url for url in requests)
    assert requests.count("registry-1.docker.io/v2/library/nginx/tags/list") == 1


async def test_the_check_stores_and_shows_the_newer_version(
    client: Any, db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _add_machine(
        db_session_factory,
        docker_status="ok",
        monitoring_updated_at=datetime.now(UTC),
        docker_containers=[
            {"name": "web", "image": "nginx:1.27.1", "state": "running"},
            {"name": "app", "image": "app:latest", "state": "running"},
        ],
    )

    async def fake_check(*_args: Any, **_kwargs: Any) -> Any:
        return (
            {"nginx:1.27.1": "current", "app:latest": "update"},
            {"app:latest": {"local_version": "2.3.0", "remote_version": "2.4.1"}},
            {},
        )

    async def fake_describe(images: dict[str, dict[str, str]]) -> dict[str, dict[str, Any]]:
        return {
            "nginx:1.27.1": {"series": "1.27.3", "newest": "1.29.0"},
            "app:latest": images["app:latest"],
        }

    monkeypatch.setattr(jobs, "check_images", fake_check)
    monkeypatch.setattr(image_versions, "describe", fake_describe)

    result = await jobs._check_machine_image_updates(str(machine_id))
    page = await client.get(f"/machines/{machine_id}/docker")
    headers = await _api_token(client)
    api = (
        await client.get(f"/api/v1/machines/{machine_id}/hardware", headers=headers)
    ).json()

    assert result == {"ok": True, "updates": 1}
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None and machine.docker_image_versions is not None
    assert "Newer in this series: 1.27.3" in page.text and "Newest: 1.29.0" in page.text
    assert "New image under this tag: version 2.4.1 (running 2.3.0)" in page.text
    assert api["docker_image_versions"]["nginx:1.27.1"] == {"series": "1.27.3", "newest": "1.29.0"}
