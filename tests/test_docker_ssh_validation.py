"""Every value that reaches a Docker command line on a machine is checked
first: names, image references, Git sources, paths, restic settings and
detached job ids (`app.ssh.docker_*`, `app.ssh.restic`,
`app.ssh.detached_jobs`). Good input is accepted, anything that could
smuggle in a shell metacharacter, an option or a path escape is refused."""

from __future__ import annotations

import uuid

import pytest

from app.ssh import detached_jobs
from app.ssh.docker_cli import (
    DockerCommandError,
    is_image_id_valid,
    is_image_ref_valid,
    is_image_valid,
    is_network_name_valid,
    is_project_name_valid,
    is_volume_name_valid,
)
from app.ssh.docker_compose import is_branch_valid, is_git_url_valid, normalize_compose_path
from app.ssh.docker_files import Target, normalize_path
from app.ssh.restic import (
    ResticConfig,
    is_repository_valid,
    is_snapshot_valid,
    normalize_host_path,
    parse_env_lines,
    redact_repository,
)

# Shapes of injection every name validator must refuse.
_HOSTILE = [
    "",
    "-rm",
    "--privileged",
    "a b",
    "a;id",
    "$(id)",
    "`id`",
    "a\nb",
    "a|b",
    "a&b",
    "a'b",
    'a"b',
    "a>b",
]

_IMAGE_ID = "sha256:" + "a" * 64


@pytest.mark.parametrize("name", ["web", "my-stack", "immich_2", "0abc"])
def test_project_names_docker_compose_accepts(name: str) -> None:
    assert is_project_name_valid(name)


@pytest.mark.parametrize("name", [*_HOSTILE, "Upper", "_lead", "a.b", "a/b", "x" * 64])
def test_project_names_that_are_refused(name: str) -> None:
    assert not is_project_name_valid(name)


@pytest.mark.parametrize("name", ["pgdata", "immich_model-cache", "a.b", "A1", "f" * 64])
def test_volume_and_network_names_accepted(name: str) -> None:
    assert is_volume_name_valid(name)
    assert is_network_name_valid(name)


@pytest.mark.parametrize("name", [*_HOSTILE, ".hidden", "_lead", "a/b", "../x", "x" * 256])
def test_volume_and_network_names_refused(name: str) -> None:
    assert not is_volume_name_valid(name)
    assert not is_network_name_valid(name)


@pytest.mark.parametrize(
    "ref",
    [
        "nginx",
        "nginx:1.27",
        "ghcr.io/immich-app/immich-server:release",
        "registry.local:5000/team/app:v1.2.3",
        "postgres:16@sha256:" + "b" * 64,
        "lscr.io/linuxserver/plex:1.40.0+abc",
    ],
)
def test_image_references_accepted(ref: str) -> None:
    assert is_image_ref_valid(ref)
    assert is_image_valid(ref)


@pytest.mark.parametrize("ref", [*_HOSTILE, "a..b", "../etc", "nginx:1.27 --rm", "a\\b"])
def test_image_references_refused(ref: str) -> None:
    assert not is_image_ref_valid(ref)
    assert not is_image_valid(ref)


def test_image_ids_are_full_sha256_digests_only() -> None:
    assert is_image_id_valid(_IMAGE_ID)
    assert is_image_valid(_IMAGE_ID)
    for value in ("sha256:" + "a" * 63, "sha256:" + "A" * 64, "a" * 64, _IMAGE_ID + ";id"):
        assert not is_image_id_valid(value)


# --- Git sources of managed stacks -------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/acme/stacks",
        "https://github.com/acme/stacks.git",
        "https://git.example.org:8443/team/infra",
    ],
)
def test_https_git_urls_accepted(url: str) -> None:
    assert is_git_url_valid(url)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://github.com/acme/stacks",
        "ssh://git@github.com/acme/stacks",
        "git@github.com:acme/stacks.git",
        "file:///etc/passwd",
        "ext::sh -c id",
        "https://user:token@github.com/acme/stacks",
        "https://github.com/",
        "https://github.com/acme/stacks?x=1",
        "https://github.com/acme/stacks#frag",
        "https://github.com/acme/st acks",
        "https://github.com/acme/stacks\nid",
        "https://github.com/acme/'stacks",
        "-https://github.com/acme/stacks",
        "https://github.com$(id)/x",
    ],
)
def test_git_urls_refused(url: str) -> None:
    assert not is_git_url_valid(url)


@pytest.mark.parametrize("branch", ["main", "release/1.2", "v1.0.0", "feature_x-y"])
def test_branches_accepted(branch: str) -> None:
    assert is_branch_valid(branch)


@pytest.mark.parametrize("branch", [*_HOSTILE, "a..b", "main.lock", "/main", ".hidden"])
def test_branches_refused(branch: str) -> None:
    assert not is_branch_valid(branch)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("compose.yaml", "compose.yaml"),
        ("/deploy/compose.yml", "deploy/compose.yml"),
        ("apps/./web/compose.yaml", "apps/web/compose.yaml"),
        ("apps/x/../compose.yaml", "apps/compose.yaml"),
        ("my stack/compose.yaml", "my stack/compose.yaml"),
    ],
)
def test_compose_paths_normalized_inside_the_repository(path: str, expected: str) -> None:
    assert normalize_compose_path(path) == expected


@pytest.mark.parametrize(
    "path",
    ["", "/", ".", "../compose.yaml", "a/../../etc/passwd", "a\\b", "a\0b", "$(id).yml",
     "a;b.yml", 'a"b.yml', "x" * 256],
)
def test_compose_paths_refused(path: str) -> None:
    assert normalize_compose_path(path) is None


# --- Paths in container and volume browsing ----------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/etc/nginx", "/etc/nginx"),
        ("etc/nginx/", "/etc/nginx"),
        ("//srv//data", "/srv/data"),
        ("/a/b/../c", "/a/c"),
        ("/../../etc", "/etc"),
    ],
)
def test_browse_paths_normalized(path: str, expected: str) -> None:
    assert normalize_path(path) == expected


@pytest.mark.parametrize("path", ["", "/a\nb", "/a\rb", "/a\0b", "/" + "x" * 4096])
def test_browse_paths_refused(path: str) -> None:
    with pytest.raises(DockerCommandError):
        normalize_path(path)


def test_a_volume_path_never_leaves_the_mount() -> None:
    volume = Target("volume", "pgdata")

    assert volume.inside("/") == "/data"
    assert volume.inside("/../../etc/shadow") == "/data/etc/shadow"
    assert Target("container", "web").inside("/../etc") == "/etc"


@pytest.mark.parametrize(
    ("kind", "name"),
    [("container", "-it"), ("container", "a;b"), ("volume", "../x"), ("image", "web")],
)
def test_a_target_with_a_bad_name_or_kind_is_refused(kind: str, name: str) -> None:
    with pytest.raises(DockerCommandError):
        Target(kind, name)  # type: ignore[arg-type]


# --- restic ------------------------------------------------------------------


@pytest.mark.parametrize(
    "repository",
    [
        "/srv/backups/restic",
        "s3:s3.amazonaws.com/bucket/restic",
        "b2:bucket:path",
        "rest:https://backup.local:8000/repo",
    ],
)
def test_restic_repositories_accepted(repository: str) -> None:
    assert is_repository_valid(repository)


@pytest.mark.parametrize(
    "repository",
    ["", "/", "/proc", "/run/", "/srv/a:b", "sftp:host:/x", "rclone:remote:x", "relative/path",
     "s3:bucket\nid", "/srv/'x", "local:/srv"],
)
def test_restic_repositories_refused(repository: str) -> None:
    assert not is_repository_valid(repository)


def test_rest_repository_credentials_are_redacted() -> None:
    assert (
        redact_repository("rest:https://alice:s3cret@backup.local:8000/repo")
        == "rest:https://***@backup.local:8000/repo"
    )
    assert redact_repository("rest:https://backup.local/repo") == "rest:https://backup.local/repo"
    assert redact_repository("s3:host/bucket") == "s3:host/bucket"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/srv/app", "/srv/app"),
        ("/srv/app/", "/srv/app"),
        ("/srv/../etc", "/etc"),
        ("/procfs-data", "/procfs-data"),
        ("/opt/my data", "/opt/my data"),
    ],
)
def test_host_paths_that_may_be_backed_up(path: str, expected: str) -> None:
    assert normalize_host_path(path) == expected


@pytest.mark.parametrize(
    "path", ["", "srv/app", "/", "/proc", "/proc/1", "/sys/class", "/dev/sda", "/run/docker.sock",
             "/srv/../proc", "/a:b", "/a\nb"],
)
def test_host_paths_refused(path: str) -> None:
    assert normalize_host_path(path) is None


def test_restic_env_lines_keep_values_and_refuse_bad_or_reserved_keys() -> None:
    text = "# S3\nAWS_ACCESS_KEY_ID=AKIA\n\nAWS_SECRET_ACCESS_KEY=a=b c\n"
    assert parse_env_lines(text) == ["AWS_ACCESS_KEY_ID=AKIA", "AWS_SECRET_ACCESS_KEY=a=b c"]
    for bad in ("lower=1", "NOEQUALS", "RESTIC_PASSWORD=x", "A-B=1", "$(id)=1"):
        with pytest.raises(DockerCommandError):
            parse_env_lines(bad)


@pytest.mark.parametrize("snapshot", ["latest", "a1b2c3d4", "f" * 64])
def test_snapshot_ids_accepted(snapshot: str) -> None:
    assert is_snapshot_valid(snapshot)


@pytest.mark.parametrize("snapshot", ["", "abc", "LATEST", "a1b2c3d4;id", "--delete", "g" * 8])
def test_snapshot_ids_refused(snapshot: str) -> None:
    assert not is_snapshot_valid(snapshot)


def _config(**overrides: object) -> ResticConfig:
    values: dict[str, object] = {
        "backup_id": str(uuid.uuid4()),
        "host": "nas",
        "repository": "/srv/restic",
        "password": "pw",
        "volumes": ["pgdata"],
    }
    values.update(overrides)
    return ResticConfig(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"backup_id": "1; reboot"},
        {"repository": "sftp:host:/x"},
        {"password": ""},
        {"password": "a\nb"},
        {"volumes": ["../etc"]},
        {"paths": ["/proc"]},
        {"paths": ["/srv/../srv/x"]},  # must already be normalized
        {"excludes": ["a\nb"]},
        {"env": ["RESTIC_REPOSITORY=/elsewhere"]},
        {"volumes": [f"v{i}" for i in range(51)]},
    ],
)
def test_a_restic_config_with_any_bad_part_is_refused(overrides: dict[str, object]) -> None:
    with pytest.raises(DockerCommandError):
        _config(**overrides).validate()


def test_restic_host_name_is_sanitized() -> None:
    assert _config(host="My NAS; rm -rf").restic_host == "My-NAS--rm--rf"
    assert _config(host="").restic_host == "debcontrol"


# --- Detached jobs -----------------------------------------------------------


@pytest.mark.parametrize(
    ("area", "job_id"),
    [
        ("docker", "x; reboot"),
        ("docker", str(uuid.uuid4()).upper()),
        ("Docker", str(uuid.uuid4())),
        ("../etc", str(uuid.uuid4())),
        ("docker stack", str(uuid.uuid4())),
    ],
)
def test_detached_job_area_and_id_are_checked(area: str, job_id: str) -> None:
    with pytest.raises(ValueError):
        detached_jobs.build_start_command(area, job_id)
    with pytest.raises(ValueError):
        detached_jobs.build_poll_command(area, job_id, 0)
    with pytest.raises(ValueError):
        detached_jobs.build_cleanup_command(area, job_id)
