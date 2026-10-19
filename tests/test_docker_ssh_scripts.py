"""The shell scripts debcontrol sends to a machine for Docker work
(`app.ssh.docker_*`, `app.ssh.restic`, `app.ssh.detached_jobs`).

Where it matters most — quoting, heredocs carrying secrets, what happens
when a step fails — the scripts are run for real with a local `sh`, `$D`
pointing at a shell function standing in for `docker`, so the test sees the
exact arguments docker would get."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import stat
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest

from app.ssh import detached_jobs
from app.ssh.docker_cli import (
    BUSYBOX_IMAGE,
    DOCKER_ACCESS_PROBE,
    EXIT_MARKER,
    DockerCommandError,
    build_shell_command,
    parse_wrapped,
    wrap,
)
from app.ssh.docker_compose import (
    MAX_FILE_BYTES,
    GitSource,
    build_deploy_script,
    build_read_file_command,
    build_remote_head_command,
    build_remove_script,
    build_stack_action_script,
    build_write_file_script,
    normalize_stack_directory,
)
from app.ssh.docker_files import (
    Target,
    build_delete_command,
    build_list_command,
    build_mkdir_command,
    build_read_command,
    build_write_command,
    parse_listing,
)
from app.ssh.docker_inventory import SECTIONS, build_inventory_command
from app.ssh.docker_prune import PruneOptions, build_prune_script
from app.ssh.docker_scan import MAX_IMAGES, build_scan_script
from app.ssh.docker_update import (
    ContainerPlan,
    build_create_payload,
    build_plan_command,
    build_pull_script,
    build_recreate_script,
    build_retag_command,
)
from app.ssh.restic import (
    ResticConfig,
    build_backup_script,
    build_check_script,
    build_forget_script,
    build_restore_script,
    build_restore_to_script,
    build_snapshots_script,
    normalize_snapshot_path,
)

_OLD = "sha256:" + "1" * 64
_NEW = "sha256:" + "2" * 64

# `$D` as a function printing each argument on its own line, in <>.
_ECHO_DOCKER = "dc_d() { for a in \"$@\"; do printf '<%s>\\n' \"$a\"; done; }; D=dc_d\n"


def _sh(
    script: str, home: Path, *, prelude: str = _ECHO_DOCKER, path: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "HOME": str(home), "TMPDIR": str(home)}
    if path is not None:
        env["PATH"] = path
    return subprocess.run(  # noqa: S603 - the script under test, run locally
        ["sh", "-c", prelude + script],  # noqa: S607
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def _args(output: str) -> list[str]:
    """The arguments `_ECHO_DOCKER` printed, in order."""
    return [
        line[1:-1] for line in output.splitlines() if line.startswith("<") and line.endswith(">")
    ]


# --- docker_cli --------------------------------------------------------------


def test_a_wrapped_script_reports_its_output_and_exit_status(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "docker"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)

    done = _sh(wrap("echo hello; exit 7"), tmp_path, prelude="",
               path=f"{bin_dir}:{os.environ['PATH']}")
    result = parse_wrapped(done.stdout)

    assert (result.output, result.exit_status) == ("hello", 7)
    assert done.stdout.rstrip().endswith(f"{EXIT_MARKER}7")


def test_a_container_shell_quotes_the_name_and_reports_missing_access() -> None:
    command = build_shell_command("web.1")

    assert "exec $D exec -it -e TERM=xterm-256color web.1 sh -c " in command
    # The probe's machine-readable answer is replaced by a readable one.
    assert DOCKER_ACCESS_PROBE not in command
    assert "exit 3" in command
    for bad in ("-u0", "a;b", "$(id)"):
        with pytest.raises(DockerCommandError):
            build_shell_command(bad)


# --- docker_compose ----------------------------------------------------------


def test_stack_actions_pass_names_and_paths_as_single_arguments(tmp_path: Path) -> None:
    workdir = "/opt/my 'stack'"
    script = build_stack_action_script(
        "media", "update", working_dir=workdir, files=[f"{workdir}/compose.yml"]
    )

    args = _args(_sh(script, tmp_path).stdout)

    expected = ["compose", "-p", "media", "--project-directory", workdir,
                "-f", f"{workdir}/compose.yml"]
    assert args == [*expected, "pull", *expected, "up", "-d", "--remove-orphans"]


@pytest.mark.parametrize("action", ["restart", "stop", "start", "down"])
def test_actions_that_need_no_files_work_from_the_name_alone(action: str) -> None:
    script = build_stack_action_script("media", action, working_dir="/opt/media",
                                       files=["/opt/media/compose.yml"])

    assert "-f " not in script and "--project-directory" not in script
    assert f"$D compose -p media {action}" in script
    # Never removes data.
    assert " -v" not in script and "--volumes" not in script


def test_stack_actions_refuse_bad_input() -> None:
    with pytest.raises(DockerCommandError):
        build_stack_action_script("media", "rm -rf /")
    with pytest.raises(DockerCommandError):
        build_stack_action_script("media", "up")  # no files known
    with pytest.raises(DockerCommandError):
        build_stack_action_script("media;id", "stop")


def test_reading_a_compose_file_needs_an_absolute_plain_path() -> None:
    command = build_read_file_command("/opt/my stack/compose.yml")

    assert "head -c 524288 '/opt/my stack/compose.yml'" in command
    assert "-v '/opt/my stack/compose.yml':/dc-file:ro" in command
    for bad in ("compose.yml", "/a:/b", "/a\0b", "/" + "x" * 1024):
        with pytest.raises(DockerCommandError):
            build_read_file_command(bad)


def test_a_deployed_stack_writes_its_files_verbatim(tmp_path: Path) -> None:
    compose = "services:\n  app:\n    image: nginx\n    command: echo $HOME `id` '$(x)'\n"
    env = "PASSWORD=p$ss`word'\"\n"

    done = _sh(build_deploy_script("web", compose=compose, env=env), tmp_path)

    stack = tmp_path / ".local/share/debcontrol/stacks/web"
    assert done.returncode == 0, done.stderr
    assert (stack / "compose.yaml").read_text() == compose
    assert (stack / ".env").read_text() == env
    assert stat.S_IMODE((stack / ".env").stat().st_mode) == 0o600
    assert done.stdout.splitlines()[-1] == "@@DC_DONE"
    args = _args(done.stdout)
    assert args[:7] == ["compose", "-p", "web", "-f", str(stack / "compose.yaml"),
                        "--env-file", str(stack / ".env")]
    assert "pull" in args and args[-3:] == ["up", "-d", "--remove-orphans"]


def test_a_failing_compose_step_is_reported_and_stops_the_deploy(tmp_path: Path) -> None:
    failing = "dc_d() { case \"$*\" in *config*) return 1;; esac; }; D=dc_d\n"

    done = _sh(build_deploy_script("web", compose="services: {}\n", pull=False), tmp_path,
               prelude=failing)

    assert done.returncode == 1
    assert "@@DC_FAILED config" in done.stdout
    assert "@@DC_STEP up" not in done.stdout
    assert "@@DC_STEP pull" not in done.stdout


def test_a_git_token_only_ever_reaches_git_through_its_env_file(tmp_path: Path) -> None:
    token = "ghp_S3cr3tT0ken"
    source = GitSource(url="https://github.com/acme/stacks", branch="main",
                       compose_path="web/compose.yaml", token=token)
    # Prints the arguments, and the env file's content as ENV: lines.
    recording = (
        "dc_d() { prev=; for a in \"$@\"; do printf '<%s>\\n' \"$a\"; "
        "[ \"$prev\" = --env-file ] && [ -f \"$a\" ] && sed 's/^/ENV:/' \"$a\"; prev=$a; done; }; "
        "D=dc_d\n"
    )

    script = build_deploy_script("web", git=source)
    done = _sh(script, tmp_path, prelude=recording)

    assert script.count(token) == 1  # inside the env-file heredoc
    assert f"ENV:DC_GIT_TOKEN={token}" in done.stdout
    assert "ENV:DC_GIT_USER=x-access-token" in done.stdout
    assert not any(token in arg for arg in _args(done.stdout))
    # Nothing was cloned by the stand-in, so the compose file is missing.
    assert "@@DC_FAILED compose_missing" in done.stdout


def test_deploy_scripts_refuse_bad_stacks() -> None:
    good_git = GitSource(url="https://github.com/acme/stacks", branch="main",
                         compose_path="compose.yaml")
    bad_calls: list[dict[str, Any]] = [
        {"name": "Web", "compose": "x"},
        {"name": "web"},
        {"name": "web", "compose": "x", "git": good_git},
        {"name": "web", "compose": "a\nDC_COMPOSE_END\nrm -rf /\n"},
        {"name": "web", "compose": "x", "env": "DC_ENV_END"},
        {"name": "web", "compose": "x" * (MAX_FILE_BYTES + 1)},
        {"name": "web", "compose": "a\0b"},
        {"name": "web", "git": GitSource("http://github.com/a/b", "main", "compose.yaml")},
        {"name": "web", "git": GitSource("https://github.com/a/b", "a..b", "compose.yaml")},
        {"name": "web", "git": GitSource("https://github.com/a/b", "main", "../compose.yaml")},
        {"name": "web", "git": GitSource("https://github.com/a/b", "main", "c.yml", "a\nb")},
    ]
    for call in bad_calls:
        name = call.pop("name")
        with pytest.raises(DockerCommandError):
            build_deploy_script(name, **call)


def test_removing_a_stack_deletes_volumes_only_when_asked() -> None:
    keep = build_remove_script("web", volumes=False)
    wipe = build_remove_script("web", volumes=True)

    assert "down --remove-orphans ||" in keep
    assert "down --remove-orphans -v ||" in wipe
    assert 'rm -rf -- "$dir"' in keep
    with pytest.raises(DockerCommandError):
        build_remove_script("../web", volumes=False)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", ""),
        ("  ", ""),
        ("/opt/my-app", "/opt/my-app"),
        ("/opt/my app/", "/opt/my app"),
        ("//srv//apps/./web", "/srv/apps/web"),
        ("~/stacks/web", "~/stacks/web"),
        ("/home/kuba/apps", "/home/kuba/apps"),
        ("/var/lib/apps/web", "/var/lib/apps/web"),
        ("/tmp/x", "/tmp/x"),  # noqa: S108 - a path string, never used
        ("relative/dir", None),
        ("~", None),
        ("~root/x", None),
        ("/opt/../etc", None),
        ("/", None),
        ("/home", None),
        ("/opt", None),
        ("/etc/web", None),
        ("/usr/local/web", None),
        ("/var/lib/docker/volumes/x", None),
        ("/opt/$(id)", None),
        ("/opt/a'b", None),
        ("/opt/a\nb", None),
        ("/-rf", None),
        ("/" + "x" * 1024, None),
    ],
)
def test_a_stack_directory_is_absolute_plain_and_not_a_system_one(
    value: str, expected: str | None
) -> None:
    assert normalize_stack_directory(value) == expected


def test_a_stack_goes_into_its_chosen_directory(tmp_path: Path) -> None:
    target = tmp_path / "apps" / "my web"
    script = build_deploy_script(
        "web", compose="services: {}\n", pull=False, directory=str(target)
    )

    done = _sh(script, tmp_path)

    assert done.returncode == 0, done.stderr
    assert (target / "compose.yaml").read_text() == "services: {}\n"
    assert (target / ".debcontrol-stack").read_text() == "web\n"
    assert str(target / "compose.yaml") in _args(done.stdout)
    # Deploying again into its own directory is fine.
    assert _sh(script, tmp_path).returncode == 0
    # A home-relative directory lands under $HOME.
    home = _sh(build_deploy_script("web", compose="services: {}\n", pull=False,
                                   directory="~/stacks/web"), tmp_path)
    assert home.returncode == 0, home.stderr
    assert (tmp_path / "stacks/web/compose.yaml").exists()


def test_a_chosen_directory_with_other_files_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "busy"
    target.mkdir()
    (target / "compose.yaml").write_text("theirs\n")
    other = tmp_path / "other"
    other.mkdir()
    (other / ".debcontrol-stack").write_text("api\n")

    for directory in (target, other):
        done = _sh(build_deploy_script("web", compose="services: {}\n", pull=False,
                                       directory=str(directory)), tmp_path)
        assert done.returncode == 1
        assert "@@DC_FAILED directory_not_empty" in done.stdout
    assert (target / "compose.yaml").read_text() == "theirs\n"
    assert (other / ".debcontrol-stack").read_text() == "api\n"
    with pytest.raises(DockerCommandError):
        build_deploy_script("web", compose="services: {}\n", directory="/etc/web")


def test_removing_a_stack_in_a_chosen_directory_keeps_other_files(tmp_path: Path) -> None:
    target = tmp_path / "apps"
    _sh(build_deploy_script("web", compose="services: {}\n", pull=False,
                            directory=str(target)), tmp_path)
    (target / "data.txt").write_text("keep me\n")

    done = _sh(build_remove_script("web", volumes=False, directory=str(target)), tmp_path)

    assert done.returncode == 0, done.stderr
    assert sorted(p.name for p in target.iterdir()) == ["data.txt"]
    # Once nothing else is left, the directory goes too.
    (target / "data.txt").unlink()
    _sh(build_deploy_script("web", compose="services: {}\n", pull=False,
                            directory=str(target)), tmp_path)
    _sh(build_remove_script("web", volumes=False, directory=str(target)), tmp_path)
    assert not target.exists()
    # Not this stack's directory (no marker of its own): nothing is deleted.
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "compose.yaml").write_text("theirs\n")
    _sh(build_remove_script("web", volumes=False, directory=str(foreign)), tmp_path)
    assert (foreign / "compose.yaml").exists()


def _sh_input(
    script: str, home: Path, stdin: str, prelude: str = _ECHO_DOCKER
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "HOME": str(home), "TMPDIR": str(home)}
    return subprocess.run(  # noqa: S603 - the script under test, run locally
        ["sh", "-c", prelude + script],  # noqa: S607
        capture_output=True,
        text=True,
        env=env,
        input=stdin,
        timeout=30,
    )


def test_a_compose_file_is_rewritten_in_place_and_checked(tmp_path: Path) -> None:
    compose = tmp_path / "my app" / "compose.yaml"
    compose.parent.mkdir()
    compose.write_text("services: {}\n")
    compose.chmod(0o640)
    new = "services:\n  web:\n    image: nginx\n    command: echo $HOME `id` '$(x)'\n"
    script = build_write_file_script(
        "app", str(compose), working_dir=str(compose.parent), files=[str(compose)]
    )

    done = _sh_input(script, tmp_path, new)

    assert done.returncode == 0, done.stderr
    assert compose.read_text() == new
    assert stat.S_IMODE(compose.stat().st_mode) == 0o640
    args = _args(done.stdout)
    assert args[:5] == ["compose", "-p", "app", "--project-directory", str(compose.parent)]
    assert args[-2:] == ["config", "-q"]
    assert done.stdout.splitlines()[-1] == "@@DC_DONE"


def test_a_compose_file_compose_rejects_is_put_back(tmp_path: Path) -> None:
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n")
    failing = (
        "dc_d() { case \"$*\" in *config*) echo 'yaml: line 2: bad'; return 1;; esac; }; "
        "D=dc_d\n"
    )
    script = build_write_file_script("app", str(compose), files=[str(compose)])

    done = _sh_input(script, tmp_path, "services: [broken\n", prelude=failing)

    assert done.returncode == 1
    assert "@@DC_FAILED config" in done.stdout
    assert "yaml: line 2: bad" in done.stdout
    assert compose.read_text() == "services: {}\n"
    too_big = _sh_input(script, tmp_path, "x" * (MAX_FILE_BYTES + 1))
    assert "@@DC_FAILED write" in too_big.stdout
    assert compose.read_text() == "services: {}\n"


def test_writing_a_compose_file_needs_one_of_the_projects_files() -> None:
    with pytest.raises(DockerCommandError):
        build_write_file_script("app", "/etc/passwd", files=["/srv/app/compose.yaml"])
    for bad in ("compose.yml", "/a:/b", "/a\0b"):
        with pytest.raises(DockerCommandError):
            build_write_file_script("app", bad, files=[bad])
    with pytest.raises(DockerCommandError):
        build_write_file_script("bad;name", "/srv/c.yaml", files=["/srv/c.yaml"])
    # Not writable as the account: through a helper container, from stdin.
    script = build_write_file_script("app", "/srv/c.yaml", files=["/srv/c.yaml"])
    assert f"-i -v /srv/c.yaml:/dc-file {BUSYBOX_IMAGE} sh -c 'cat > /dc-file'" in script


def test_the_remote_head_check_keeps_the_token_off_the_command_line() -> None:
    source = GitSource("https://github.com/acme/stacks", "main", "compose.yaml", "user:pa55")
    command = build_remote_head_command(source)

    heredoc, _, run_line = command.partition("DC_GIT_ENV_END\n$D run")
    assert "DC_GIT_USER=user" in heredoc and "DC_GIT_TOKEN=pa55" in heredoc
    assert "pa55" not in run_line
    assert "--pull missing" in run_line
    with pytest.raises(DockerCommandError):
        build_remote_head_command(GitSource("ext::sh", "main", "compose.yaml"))


# --- docker_files ------------------------------------------------------------


def test_a_listing_runs_for_real_and_parses(tmp_path: Path) -> None:
    root = tmp_path / "srv"
    (root / "conf.d").mkdir(parents=True)
    (root / "my file.txt").write_text("hello")
    (root / "-rf").write_text("")
    (root / ".hidden").write_text("")
    # `$D exec <container> ...` runs the rest locally.
    local_exec = "dc_d() { shift 2; \"$@\"; }; D=dc_d\n"

    done = _sh(build_list_command(Target("container", "web"), str(root)), tmp_path,
               prelude=local_exec)
    missing = _sh(build_list_command(Target("container", "web"), str(root / "nope")), tmp_path,
                  prelude=local_exec)

    entries = parse_listing(done.stdout)
    assert entries is not None
    assert [(e["name"], e["kind"]) for e in entries] == [
        ("conf.d", "dir"), ("-rf", "file"), (".hidden", "file"), ("my file.txt", "file")]
    assert parse_listing(missing.stdout) is None


def test_container_commands_quote_every_path(tmp_path: Path) -> None:
    target = Target("container", "web")
    path = "/srv/it's here; rm -rf ~"

    args = _args(_sh(build_mkdir_command(target, path), tmp_path).stdout)

    assert args[:3] == ["exec", "web", "sh"]
    assert args[-1] == path
    assert build_read_command(target, path, 100).endswith("| head -c 101")
    assert build_write_command(target, "/srv/a b") == "$D cp -a - web:'/srv/a b'"


def test_a_volume_is_mounted_read_only_unless_written_and_never_networked() -> None:
    volume = Target("volume", "pgdata")

    listing = build_list_command(volume, "/")
    writing = build_write_command(volume, "/conf")
    deleting = build_delete_command(volume, "/old")

    assert "-v pgdata:/data:ro" in listing
    assert "-v pgdata:/data " in writing and "-i " in writing
    assert "-v pgdata:/data " in deleting
    for command in (listing, writing, deleting):
        assert "--network none" in command
        assert "--privileged" not in command
    assert build_read_command(volume, "/-x", 10).count("./$2") == 1


@pytest.mark.parametrize("target", [Target("container", "web"), Target("volume", "pgdata")])
def test_the_top_directory_is_never_deleted(target: Target) -> None:
    for path in ("/", "/..", "//"):
        with pytest.raises(DockerCommandError):
            build_delete_command(target, path)


# --- docker_inventory --------------------------------------------------------


def test_the_inventory_reads_only_known_sections_in_order() -> None:
    command = build_inventory_command(["df", "images", "bogus"])

    assert command.index("===IMAGES===") < command.index("===DF===")
    assert "===BOGUS===" not in command and "===INSPECT===" not in command
    assert set(SECTIONS) >= {"images", "inspect", "df"}
    for empty in ([], ["bogus"]):
        with pytest.raises(DockerCommandError):
            build_inventory_command(empty)


# --- docker_prune ------------------------------------------------------------


def test_prune_needs_a_selection_and_a_deliberate_all_volumes() -> None:
    with pytest.raises(DockerCommandError):
        build_prune_script(PruneOptions())
    with pytest.raises(DockerCommandError):
        build_prune_script(PruneOptions(images=True, all_volumes=True))
    with pytest.raises(DockerCommandError):
        build_prune_script(PruneOptions(all_images=True))  # a modifier alone selects nothing


def test_prune_runs_containers_first_and_carries_on_after_a_failure(tmp_path: Path) -> None:
    script = build_prune_script(PruneOptions.from_dict(
        {"networks": True, "containers": True, "images": True, "volumes": True, "bogus": True}
    ))
    failing_networks = (
        "dc_d() { echo \"ran $*\"; [ \"$1\" != network ]; }; D=dc_d\n"
    )

    done = _sh(script, tmp_path, prelude=failing_networks)

    ran = [line for line in done.stdout.splitlines() if line.startswith("ran ")]
    assert ran == ["ran container prune -f", "ran image prune -f", "ran network prune -f",
                   "ran volume prune -f"]
    assert "@@DC_FAILED networks" in done.stdout
    assert done.returncode == 1


def test_prune_all_flags_only_when_asked() -> None:
    plain = build_prune_script(PruneOptions(images=True, volumes=True))
    everything = build_prune_script(
        PruneOptions(images=True, all_images=True, volumes=True, all_volumes=True)
    )

    assert "$D image prune -f &&" in plain and "prune -f -a" not in plain
    assert "$D image prune -f -a" in everything and "$D volume prune -f -a" in everything
    assert PruneOptions.from_dict(None) == PruneOptions()


# --- docker_scan -------------------------------------------------------------


def test_a_scan_script_scans_each_image_with_both_scanners() -> None:
    script = build_scan_script(["nginx:1.27", _OLD])

    assert script.count("echo '@@DC_BEGIN trivy'") == 2
    assert script.count("echo '@@DC_BEGIN grype'") == 2
    assert "'@@DC_IMAGE nginx:1.27'" in script
    assert f"docker:{_OLD}" in script
    # The scanners only ever see the Docker socket read-only.
    assert "-v /var/run/docker.sock:/var/run/docker.sock:ro" in script
    assert "/var/run/docker.sock:/var/run/docker.sock " not in script


def test_a_scan_refuses_bad_or_too_many_images() -> None:
    for images in ([], ["nginx; id"], ["-q"], ["a"] * (MAX_IMAGES + 1)):
        with pytest.raises(DockerCommandError):
            build_scan_script(images)


# --- docker_update -----------------------------------------------------------


def test_a_pull_scans_only_when_asked() -> None:
    plain = build_pull_script("nginx:1.27", current=_OLD, scan=False)
    gated = build_pull_script("nginx:1.27", current=_OLD, scan=True, scan_old=_NEW)

    assert "$D pull nginx:1.27" in plain and "@@DC_BEGIN" not in plain
    assert f'[ "$new" != {_OLD} ]' in gated
    assert "'@@DC_IMAGE nginx:1.27'" in gated and f"'@@DC_IMAGE {_NEW}'" in gated


@pytest.mark.parametrize(
    ("ref", "current", "scan_old"),
    [
        ("nginx@sha256:" + "a" * 64, _OLD, None),  # pinned by digest: nothing to update
        (_OLD, _OLD, None),
        ("nginx;id", _OLD, None),
        ("nginx:1", "abc", None),
        ("nginx:1", _OLD, "nginx:1"),
    ],
)
def test_a_pull_refuses_what_cannot_be_updated(
    ref: str, current: str, scan_old: str | None
) -> None:
    with pytest.raises(DockerCommandError):
        build_pull_script(ref, current=current, scan=True, scan_old=scan_old)


def test_retag_and_plan_commands_validate_their_input() -> None:
    assert build_retag_command(_OLD, "nginx:1.27") == f"$D tag {_OLD} nginx:1.27"
    assert "--type container web" in build_plan_command("web")
    with pytest.raises(DockerCommandError):
        build_retag_command("nginx", "nginx:1.27")
    with pytest.raises(DockerCommandError):
        build_plan_command("web;id")


def _container_record() -> dict[str, Any]:
    cid = "abcdef123456" + "0" * 52
    return {
        "Id": cid,
        "Config": {
            "Hostname": cid[:12],
            "MacAddress": "02:42:ac:11:00:02",
            "Image": "nginx:1.27",
            "Env": ["PATH=/usr/bin", "NGINX_VERSION=1.27.0", "MY_SETTING=1"],
            "Cmd": ["nginx", "-g", "daemon off;"],
            "Labels": {"maintainer": "NGINX", "app": "web"},
            "ExposedPorts": {"80/tcp": {}, "8443/tcp": {}},
            "Volumes": {"/cache": {}},
        },
        "HostConfig": {"NetworkMode": "frontend", "Binds": ["/srv/html:/usr/share/nginx/html:ro"]},
        "Mounts": [
            {"Type": "bind", "Source": "/srv/html", "Destination": "/usr/share/nginx/html"},
            {"Type": "volume", "Name": "f" * 64, "Destination": "/cache", "RW": True},
        ],
        "NetworkSettings": {"Networks": {
            "backend": {"Aliases": ["web", cid[:12]], "IPAMConfig": {"IPv4Address": "10.0.0.5"}},
            "frontend": {"Aliases": ["web"], "IPAMConfig": None},
        }},
    }


def test_a_recreate_payload_drops_the_old_images_defaults_and_keeps_the_containers_own() -> None:
    image = {"Config": {
        "Env": ["PATH=/usr/bin", "NGINX_VERSION=1.27.0"],
        "Cmd": ["nginx", "-g", "daemon off;"],
        "Labels": {"maintainer": "NGINX"},
        "ExposedPorts": {"80/tcp": {}},
        "Volumes": {"/cache": {}},
    }}

    payload, extra = build_create_payload(_container_record(), image)

    assert payload["Env"] == ["MY_SETTING=1"]
    assert payload["Labels"] == {"app": "web"}
    assert "Cmd" not in payload  # the new image's default applies
    assert payload["ExposedPorts"] == {"8443/tcp": {}}
    assert payload["Volumes"] is None
    assert "Hostname" not in payload and "MacAddress" not in payload
    # The anonymous volume is carried over, not replaced by an empty one.
    assert payload["HostConfig"]["Binds"] == [
        "/srv/html:/usr/share/nginx/html:ro", f"{'f' * 64}:/cache"]
    # Created on its own network mode's network, the other connected after.
    assert list(payload["NetworkingConfig"]["EndpointsConfig"]) == ["frontend"]
    assert extra == [{"name": "backend", "aliases": ["web"], "ipv4": "10.0.0.5", "ipv6": ""}]


def test_a_host_networked_container_joins_no_networks() -> None:
    record = _container_record()
    record["HostConfig"]["NetworkMode"] = "host"

    payload, extra = build_create_payload(record, {})

    assert "NetworkingConfig" not in payload and extra == []


def _plan(**overrides: Any) -> ContainerPlan:
    values: dict[str, Any] = {"name": "web", "container_id": "c" * 64, "ref": "nginx:1.27",
                              "image_id": _OLD, "running": True}
    values.update(overrides)
    return ContainerPlan(**values)


def test_a_compose_service_is_recreated_by_compose_with_quoted_values() -> None:
    plan = _plan(compose_project="media", compose_service="my service",
                 compose_working_dir="/opt/my media", compose_files=["/opt/my media/c.yml"])

    script = build_recreate_script(plan, previous_image_id=_OLD)

    compose = "$D compose -p media --project-directory '/opt/my media' -f '/opt/my media/c.yml'"
    assert f"{compose} up -d --no-deps 'my service'" in script
    assert f"$D tag {_OLD} nginx:1.27 && {compose} up -d --no-deps 'my service'" in script
    assert "containers/create" not in script


def test_a_plain_container_is_recreated_from_its_payload_with_a_way_back() -> None:
    payload, extra = build_create_payload(_container_record(), {})

    script = build_recreate_script(_plan(), payload=payload, extra_networks=extra,
                                   retag_to=_NEW)

    lines = script.splitlines()
    body = lines[lines.index("DC_PAYLOAD_END") - 1]
    assert json.loads(body) == payload
    assert script.index(f"$D tag {_NEW} nginx:1.27 || exit 4") < script.index("@@DC_STEP stop")
    assert "backup=web-debcontrol-old" in script
    assert "$D network connect --alias web --ip 10.0.0.5 backend \"$name\"" in script
    assert script.count("restore; exit 1") >= 3


def test_a_recreate_refuses_what_would_break_out_of_its_script() -> None:
    with pytest.raises(DockerCommandError):
        build_recreate_script(_plan())  # no payload
    with pytest.raises(DockerCommandError):
        build_recreate_script(_plan(), payload={"Cmd": ["DC_PAYLOAD_END"]})
    with pytest.raises(DockerCommandError):
        build_recreate_script(_plan(name="web;id"), payload={})
    with pytest.raises(DockerCommandError):
        build_recreate_script(_plan(), payload={}, extra_networks=[{"name": "a b"}])
    with pytest.raises(DockerCommandError):
        build_recreate_script(
            _plan(compose_project="Bad Name", compose_service="s", compose_working_dir="/x",
                  compose_files=["/x/c.yml"])
        )


# --- restic ------------------------------------------------------------------


def _restic(**overrides: Any) -> ResticConfig:
    values: dict[str, Any] = {
        "backup_id": str(uuid.UUID(int=1)),
        "host": "nas",
        "repository": "/srv/restic",
        "password": "pa$$ `word` 'x'",
        "env": ["AWS_ACCESS_KEY_ID=AKIA"],
        "volumes": ["pgdata"],
        "paths": ["/srv/my app"],
        "excludes": ["*.tmp", "cache dir"],
    }
    values.update(overrides)
    return ResticConfig(**values)


# A docker stand-in: `ps` lists two containers, `stop`/`start` report on
# stderr (the script silences their stdout),
# `run` prints restic's env file and fails a `backup`.
_RESTIC_DOCKER = (
    "dc_d() { case \"$1\" in "
    "ps) echo c1; echo c2;; "
    "stop) echo \"STOPPED $*\" >&2;; "
    "start) echo \"STARTED $*\" >&2;; "
    "run) prev=; for a in \"$@\"; do "
    "[ \"$prev\" = --env-file ] && sed 's/^/ENV:/' \"$a\"; prev=$a; "
    "[ \"$a\" = backup ] && return 1; done; return 0;; "
    "esac; }; D=dc_d\n"
)


def test_a_restic_backup_passes_secrets_by_env_file_and_restarts_containers_on_failure(
    tmp_path: Path,
) -> None:
    config = _restic()

    done = _sh(build_backup_script(config, stop_containers=True, keep={}), tmp_path,
               prelude=_RESTIC_DOCKER)

    assert f"ENV:RESTIC_PASSWORD={config.password}" in done.stdout
    assert "ENV:RESTIC_REPOSITORY=/srv/restic" in done.stdout
    assert "ENV:AWS_ACCESS_KEY_ID=AKIA" in done.stdout
    assert "STOPPED stop c1 c2" in done.stderr
    assert "@@DC_FAILED backup" in done.stdout
    # Started again by the exit trap even though the backup failed.
    assert "STARTED start c1 c2" in done.stderr
    assert done.returncode == 1
    # The temporary env file is gone.
    assert [p for p in tmp_path.iterdir() if p.name.startswith("tmp")] == []


def test_a_restic_backup_mounts_sources_read_only_and_quotes_everything() -> None:
    script = build_backup_script(_restic(), stop_containers=False,
                                 keep={"daily": 7, "weekly": 0, "monthly": None})

    assert "-v pgdata:/backup/volumes/pgdata:ro" in script
    assert "-v '/srv/my app':'/backup/paths/srv/my app':ro" in script
    assert "-v /srv/restic:/srv/restic " in script
    assert "--exclude '*.tmp' --exclude 'cache dir'" in script
    assert "--keep-daily 7 --prune" in script and "--keep-weekly" not in script
    assert "@@DC_STEP stop" not in script
    assert script.count("pa$$ `word`") == 1  # only inside the heredoc


def test_a_restore_mounts_writable_always_stops_users_and_deletes_only_when_asked() -> None:
    config = _restic()
    keep = build_restore_script(config, "latest", delete=False)
    wipe = build_restore_script(config, "a1b2c3d4", delete=True)

    assert "-v pgdata:/backup/volumes/pgdata " in keep and ":ro" not in keep
    assert "@@DC_STEP stop" in keep
    assert "--include /backup/volumes/pgdata --include '/backup/paths/srv/my app'" in keep
    assert "--delete" not in keep and " --delete " in wipe
    for snapshot in ("--delete", "latest; id", ""):
        with pytest.raises(DockerCommandError):
            build_restore_script(config, snapshot, delete=False)


# Like `_RESTIC_DOCKER`, but `run` prints every argument (to see restic's).
_RESTIC_ARGS_DOCKER = (
    "dc_d() { case \"$1\" in "
    "ps) echo c1;; stop|start) echo \"$1 $*\" >&2;; "
    "run) for a in \"$@\"; do printf '<%s>\\n' \"$a\"; done;; "
    "esac; }; D=dc_d\n"
)


def test_restore_to_puts_one_part_of_a_snapshot_into_one_volume(tmp_path: Path) -> None:
    config = _restic()

    done = _sh(
        build_restore_to_script(
            config, "a1b2c3d4", source="/backup/volumes/old data", volume="newdata", delete=True
        ),
        tmp_path,
        prelude=_RESTIC_ARGS_DOCKER,
    )

    assert done.returncode == 0, done.stderr
    args = _args(done.stdout)
    assert "newdata:/restore" in args
    assert "pgdata:/backup/volumes/pgdata" not in " ".join(args)
    assert args[-5:] == ["restore", "a1b2c3d4:/backup/volumes/old data", "--target", "/restore",
                         "--delete"]
    assert "stop stop c1" in done.stderr and "start start c1" in done.stderr
    assert "@@DC_DONE" in done.stdout


def test_restore_to_a_directory_of_a_whole_snapshot() -> None:
    script = build_restore_to_script(
        _restic(), "latest", source="/", path="/srv/restored", delete=False
    )

    assert "-v /srv/restored:/restore -v /srv/restic:/srv/restic" in script
    assert "R restore latest --target /restore ||" in script
    assert "@@DC_STEP stop" not in script
    for kwargs in (
        {"source": "/", "volume": "a", "path": "/srv/x"},
        {"source": "/"},
        {"source": "relative", "volume": "a"},
        {"source": "/a/../b", "volume": "a"},
        {"source": "/a:b", "volume": "a"},
        {"source": "/", "volume": "bad name"},
        {"source": "/", "path": "/proc/x"},
    ):
        with pytest.raises(DockerCommandError):
            build_restore_to_script(_restic(), "latest", delete=False, **kwargs)
    with pytest.raises(DockerCommandError):
        build_restore_to_script(_restic(), "x; id", source="/", volume="a", delete=False)
    assert normalize_snapshot_path("/backup//volumes/x/") == "/backup/volumes/x"
    assert normalize_snapshot_path("/") == "/"


def test_restic_maintenance_scripts() -> None:
    config = _restic()

    assert "R check ||" in build_check_script(config)
    assert "R check --read-data-subset=10% ||" in build_check_script(config, read_data_percent=10)
    assert "read-data-subset" not in build_check_script(config, read_data_percent=500)
    assert "--keep-last 3 --prune" in build_forget_script(config, keep={"last": 3})
    assert f"R snapshots --json --tag {config.tag}" in build_snapshots_script(config)
    every = build_snapshots_script(config, all_snapshots=True)
    assert "R snapshots --json\n" in every and "--tag" not in every
    with pytest.raises(DockerCommandError):
        build_forget_script(config, keep={})
    with pytest.raises(DockerCommandError):
        build_backup_script(_restic(volumes=[], paths=[]), stop_containers=False, keep={})
    with pytest.raises(DockerCommandError):
        build_check_script(_restic(password="DC_RESTIC_ENV_END"))


# --- detached_jobs -----------------------------------------------------------


class _Completed:
    def __init__(self, stdout: Any, exit_status: int) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.exit_status = exit_status


class _LocalConnection:
    """Runs each command with the local `sh`; records the command lines."""

    def __init__(self, home: Path, commands: list[str]) -> None:
        self.home = home
        self.commands = commands

    async def run(self, command: str, **kwargs: Any) -> _Completed:
        self.commands.append(command)
        env = {**os.environ, "HOME": str(self.home)}
        stdin = kwargs.get("input")
        done = await asyncio.to_thread(
            subprocess.run, ["sh", "-c", command], capture_output=True, env=env, timeout=30,
            input=stdin.encode() if isinstance(stdin, str) else stdin,
        )
        if kwargs.get("encoding", "utf-8") is None:
            return _Completed(done.stdout, done.returncode)
        return _Completed(done.stdout.decode(), done.returncode)

    async def __aenter__(self) -> _LocalConnection:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


async def test_a_detached_job_keeps_its_script_off_the_command_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    commands: list[str] = []

    async def fake_open(*_args: Any, **_kwargs: Any) -> _LocalConnection:
        return _LocalConnection(tmp_path, commands)

    monkeypatch.setattr(detached_jobs, "open_connection", fake_open)
    job = str(uuid.uuid4())
    machine: Any = object()
    secret_script = "TOKEN=hunter2-secret; echo step one; sleep 0.2; echo done; exit 5\n"

    first = await detached_jobs.start(machine, None, "docker", job, secret_script, 5)
    again = await detached_jobs.start(machine, None, "docker", job, secret_script, 5)
    result = await detached_jobs.follow(machine, None, "docker", job, 5, 30, poll_seconds=0.1)

    assert (first, again) == (True, False)
    assert (result.state, result.exit_status) == ("finished", 5)
    assert result.output == "step one\ndone\n"
    assert not any("hunter2-secret" in command for command in commands)
    assert list((tmp_path / ".local/state/debcontrol/docker").iterdir()) == []


async def test_following_an_unknown_job_reports_it_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def fake_open(*_args: Any, **_kwargs: Any) -> _LocalConnection:
        return _LocalConnection(tmp_path, [])

    monkeypatch.setattr(detached_jobs, "open_connection", fake_open)

    machine: Any = object()
    result = await detached_jobs.follow(machine, None, "docker", str(uuid.uuid4()), 5, 0)

    assert result.state == "missing"


def test_the_poll_offset_is_an_integer_in_the_command() -> None:
    command = detached_jobs.build_poll_command("docker", str(uuid.UUID(int=7)), 41)

    assert "tail -c +42 " in command
    assert shlex.split(command)  # well-formed shell
