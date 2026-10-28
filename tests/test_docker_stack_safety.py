"""Deploy safety for managed stacks (Docker upgrade #2): SSH repositories
with a deploy key, more compose files, the health check with automatic
rollback, the vulnerability gate before `up`, the check before a deploy
and the history of deployed versions — scripts run for real in `sh` with
a stand-in `docker`, jobs against a scripted fake machine."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import delete, select

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.docker import (
    DockerJob,
    DockerJobKind,
    DockerJobStatus,
    DockerStack,
    DockerStackVersion,
    StackSource,
)
from app.db.models.notification_rule import NotificationEventType
from app.db.models.role import Permission
from app.services import docker_stacks
from app.ssh.docker_cli import DockerCommandError
from app.ssh.docker_compose import (
    GitSource,
    StackFiles,
    build_remote_head_command,
    build_stack_check_script,
    build_stack_restore_script,
    build_stack_script,
    is_repository_url_valid,
    is_ssh_git_url_valid,
    normalize_known_hosts,
    parse_host_keys,
    parse_stack_images,
)
from app.tasks import docker_jobs as tasks
from tests.test_api_v1_docker import audit_actions, base, docker_machine, headers_for
from tests.test_api_v1_docker_stacks import create_stack
from tests.test_api_v1_extended import _api_token
from tests.test_docker_ssh_scripts import _args, _sh
from tests.test_docker_tasks_jobs import (
    COMMIT,
    NEW_COMMIT,
    NEW_ID,
    OLD_ID,
    FakeMachine,
    _add,
    _get,
    _job,
    _machine,
    _scan_lines,
    _stack,
    install_fake_machine,
)
from tests.test_docker_web_support import (
    Factory,
    audit_entries,
    csrf_token,
    jobs_of,
    make_docker_machine,
)

KEY_B64 = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
KNOWN = f"github.com ssh-ed25519 {KEY_B64}"
COMPOSE = "services:\n  web:\n    image: nginx:1.27\n"
COMPOSE_V2 = "services:\n  web:\n    image: nginx:1.28\n"
# The stand-in answers `ps` with the state in $STATE/$HEALTH, and never sleeps.
_HEALTH_DOCKER = (
    'dc_d() { case "$*" in '
    '*"ps -aq"*) echo c1;; '
    '*"ps -a --format"*) echo "web|${STATE:-running}|${HEALTH:-}|0";; '
    "*inspect*) echo 0;; "
    "*) :;; esac; }; D=dc_d; sleep() { :; }\n"
)


@pytest.fixture
def machine_shell(monkeypatch: pytest.MonkeyPatch, db_session_factory: Factory) -> FakeMachine:
    return install_fake_machine(monkeypatch, db_session_factory)


def _ssh_source(**overrides: Any) -> GitSource:
    values: dict[str, Any] = {
        "url": "git@github.com:acme/stacks.git",
        "branch": "main",
        "compose_path": "compose.yaml",
        "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nS3CR3T\n-----END OPENSSH PRIVATE KEY-----",
    }
    values.update(overrides)
    return GitSource(**values)


# --- Repository addresses and host keys --------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:acme/stacks.git",
        "ssh://git@github.com/acme/stacks.git",
        "ssh://git@git.example.com:2222/ops/app",
        "deploy@10.0.0.5:repos/app.git",
    ],
)
def test_ssh_repository_addresses_are_accepted(url: str) -> None:
    assert is_ssh_git_url_valid(url)
    assert is_repository_url_valid(url)


@pytest.mark.parametrize(
    "url",
    [
        "github.com:acme/stacks.git",  # no user
        "-oProxyCommand=id@host:x",
        "git@host:-oProxyCommand=id",
        "git@host:../etc/passwd",
        "ssh://git@host/a/../b",
        "ssh://git:pw@host/repo.git",
        "ssh://git@host/repo.git?x=1",
        "ssh://git@host:99999/repo.git",
        "git@ho st:repo.git",
        "ext::sh -c id",
        "git://example.com/repo.git",
        "git@host:repo;id",
    ],
)
def test_unsafe_or_odd_ssh_addresses_are_refused(url: str) -> None:
    assert not is_repository_url_valid(url)


def test_known_hosts_lines_are_checked_and_comments_dropped() -> None:
    assert normalize_known_hosts(f"# from ssh-keyscan\n\n{KNOWN}\r\n") == KNOWN
    assert normalize_known_hosts("") == ""
    for bad in ("github.com", f"{KNOWN}\nrm -rf /", f"host ssh-dss {KEY_B64}", "x" * 9000):
        assert normalize_known_hosts(bad) is None


def test_host_keys_seen_on_a_first_connection_are_parsed_and_checked() -> None:
    output = f"@@DC_HOSTKEY {KNOWN}\n@@DC_HOSTKEY junk\n@@DC_COMMIT {COMMIT}\n"
    assert parse_host_keys(output) == ""  # one bad line: none kept
    assert parse_host_keys(f"@@DC_HOSTKEY {KNOWN}\n") == KNOWN


# --- Scripts -----------------------------------------------------------------------------


def test_an_ssh_key_reaches_git_only_through_a_private_temporary_directory() -> None:
    source = _ssh_source()
    script = build_stack_script(StackFiles("web", git=source))

    assert script.count("S3CR3T") == 1  # in the key heredoc only
    assert 'cat > "$sshd/key" <<' in script
    assert 'chmod 600 "$sshd/key"' in script
    assert '-v "$sshd":/dc-ssh -v "$sshd/passwd":/etc/passwd:ro' in script
    assert "DC_SSH_STRICT=accept-new" in script  # nothing pinned yet: record it
    assert "DC_GIT_TOKEN=" not in script and "DC_GIT_USER=" not in script
    pinned = build_stack_script(StackFiles("web", git=_ssh_source(known_hosts=KNOWN)))
    assert "DC_SSH_STRICT=yes" in pinned and KNOWN in pinned


def test_a_repository_needs_a_key_exactly_when_it_is_reached_over_ssh() -> None:
    bad = [
        _ssh_source(ssh_key=""),
        GitSource("https://github.com/a/b", "main", "compose.yaml", ssh_key="k"),
        _ssh_source(known_hosts="not a host key"),
        _ssh_source(commit="main"),
        _ssh_source(overrides=("a.yaml",) * 6),
        _ssh_source(overrides=("../x.yaml",)),
    ]
    for source in bad:
        with pytest.raises(DockerCommandError):
            build_stack_script(StackFiles("web", git=source))
        with pytest.raises(DockerCommandError):
            build_remote_head_command(source)


def test_the_remote_head_check_over_ssh_mounts_the_key() -> None:
    command = build_remote_head_command(_ssh_source(known_hosts=KNOWN))

    assert "--pull missing" in command
    assert '-v "$sshd":/dc-ssh' in command
    assert "DC_SSH_STRICT=yes" in command


def test_more_compose_files_are_applied_in_order_and_git_stacks_build(tmp_path: Path) -> None:
    source = GitSource(
        "https://github.com/acme/stacks", "main", "base.yaml", overrides=("prod.yaml", "x/y.yml")
    )

    done = _sh(build_stack_script(StackFiles("web", git=source), pull=False), tmp_path)

    # The stand-in cloned nothing, so the first file is missing; the script
    # names each file it needs.
    script = build_stack_script(StackFiles("web", git=source), pull=False)
    assert "@@DC_FAILED compose_missing" in done.stdout
    assert (
        '-f "$dir/repo/base.yaml" -f "$dir/repo/prod.yaml" -f "$dir/repo/x/y.yml"' in script
    )
    assert "dc up -d --remove-orphans --build" in script
    editor = build_stack_script(StackFiles("web", compose=COMPOSE))
    assert "--build" not in editor


def test_a_healthy_deploy_passes_the_health_check(tmp_path: Path) -> None:
    files = StackFiles("web", compose=COMPOSE_V2)
    previous = StackFiles("web", compose=COMPOSE)

    done = _sh(
        build_stack_script(files, pull=False, health=True, previous=previous),
        tmp_path,
        prelude=_HEALTH_DOCKER,
    )

    assert done.returncode == 0, done.stdout + done.stderr
    assert "@@DC_STEP health" in done.stdout
    assert done.stdout.splitlines()[-1] == "@@DC_DONE"
    stack = tmp_path / ".local/share/debcontrol/stacks/web"
    assert (stack / "compose.yaml").read_text() == COMPOSE_V2


@pytest.mark.parametrize(
    ("state", "health"), [("restarting", ""), ("running", "unhealthy"), ("dead", "")]
)
def test_an_unhealthy_deploy_puts_the_previous_version_back(
    tmp_path: Path, state: str, health: str
) -> None:
    files = StackFiles("web", compose=COMPOSE_V2, env="A=2\n")
    previous = StackFiles("web", compose=COMPOSE, env="A=1\n")
    prelude = f"STATE={state}; HEALTH={health}\n" + _HEALTH_DOCKER

    done = _sh(
        build_stack_script(files, pull=False, health=True, previous=previous), tmp_path,
        prelude=prelude,
    )

    assert done.returncode == 1
    assert "Not running or unhealthy:" in done.stdout
    assert "@@DC_ROLLED_BACK" in done.stdout
    assert "@@DC_FAILED health" in done.stdout
    assert "@@DC_DONE" not in done.stdout
    stack = tmp_path / ".local/share/debcontrol/stacks/web"
    assert (stack / "compose.yaml").read_text() == COMPOSE
    assert (stack / ".env").read_text() == "A=1\n"


def test_without_a_previous_version_an_unhealthy_deploy_just_fails(tmp_path: Path) -> None:
    done = _sh(
        build_stack_script(StackFiles("web", compose=COMPOSE), pull=False, health=True),
        tmp_path,
        prelude="STATE=restarting\n" + _HEALTH_DOCKER,
    )

    assert done.returncode == 1
    assert "@@DC_FAILED health" in done.stdout
    assert "@@DC_STEP rollback" not in done.stdout


def test_a_failed_rollback_is_reported(tmp_path: Path) -> None:
    failing_up = _HEALTH_DOCKER.replace('*) :;; esac', '*" up "*) return 1;; *) :;; esac')

    done = _sh(
        build_stack_script(
            StackFiles("web", compose=COMPOSE_V2), pull=False, health=True,
            previous=StackFiles("web", compose=COMPOSE),
        ),
        tmp_path,
        prelude=failing_up,
    )

    assert done.returncode == 1
    assert "@@DC_ROLLBACK_FAILED" in done.stdout
    assert "@@DC_FAILED up" in done.stdout


def test_a_prepared_deploy_reports_images_and_stops_before_up(tmp_path: Path) -> None:
    images = (
        'dc_d() { case "$*" in '
        '*"ps -aq"*) echo c1;; '
        f'*"inspect --format @@DC_OLD"*) echo "@@DC_OLD nginx:1.27 {OLD_ID}";; '
        '*"config --images"*) echo nginx:1.27;; '
        f'*"image inspect"*) echo {NEW_ID};; '
        "*) :;; esac; }; D=dc_d\n"
    )

    done = _sh(
        build_stack_script(StackFiles("web", compose=COMPOSE), up=False, report_images=True),
        tmp_path,
        prelude=images,
    )

    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines()[-1] == "@@DC_PREPARED"
    assert "@@DC_STEP up" not in done.stdout
    assert parse_stack_images(done.stdout) == ({"nginx:1.27": OLD_ID}, {"nginx:1.27": NEW_ID})


def test_image_reports_with_odd_refs_or_ids_are_dropped() -> None:
    old, new = parse_stack_images(
        f"@@DC_OLD nginx:1.27 {OLD_ID}\n@@DC_OLD $(id) {OLD_ID}\n@@DC_NEW app:1 not-an-id\n"
    )
    assert old == {"nginx:1.27": OLD_ID}
    assert new == {"app:1": ""}


def test_a_blocked_deploy_retags_and_puts_the_previous_files_back(tmp_path: Path) -> None:
    script = build_stack_restore_script(
        "web", "", StackFiles("web", compose=COMPOSE), {"nginx:1.27": OLD_ID}
    )

    done = _sh(script, tmp_path)

    assert _args(done.stdout)[:3] == ["tag", OLD_ID, "nginx:1.27"]
    assert "@@DC_ROLLED_BACK" in done.stdout
    assert " up " not in script  # nothing is started
    assert (tmp_path / ".local/share/debcontrol/stacks/web/compose.yaml").read_text() == COMPOSE
    with pytest.raises(DockerCommandError):
        build_stack_restore_script("web", "", None, {"nginx:1.27": "x;id"})


def test_the_check_shows_the_diff_and_validates_without_touching_the_stack(
    tmp_path: Path,
) -> None:
    script = build_stack_check_script(
        StackFiles("web", compose=COMPOSE_V2, env="A=1\n"), diff="-  image: nginx:1.27"
    )

    done = _sh(script, tmp_path)

    assert done.returncode == 0, done.stderr
    assert "-  image: nginx:1.27" in done.stdout
    assert done.stdout.splitlines()[-1] == "@@DC_CHECK_OK"
    args = _args(done.stdout)
    assert args[-2:] == ["config", "-q"]
    assert "--project-directory" in args
    assert not (tmp_path / ".local/share/debcontrol/stacks/web").exists()
    failing = "dc_d() { case \"$*\" in *config*) return 1;; esac; }; D=dc_d\n"
    bad = _sh(script, tmp_path, prelude=failing)
    assert "@@DC_FAILED config" in bad.stdout and "@@DC_CHECK_OK" not in bad.stdout


def test_the_check_of_a_git_stack_compares_with_the_deployed_commit() -> None:
    source = GitSource("https://github.com/a/b", "main", "compose.yaml", "tok",
                       overrides=("prod.yaml",))
    script = build_stack_check_script(StackFiles("web", git=source), deployed_commit=COMMIT)

    assert f"DC_GIT_DEPLOYED={COMMIT}" in script
    assert "DC_GIT_PATHS=compose.yaml prod.yaml" in script
    assert '-f "$tmp/repo/compose.yaml" -f "$tmp/repo/prod.yaml"' in script
    with pytest.raises(DockerCommandError):
        build_stack_check_script(StackFiles("web", git=source), deployed_commit="HEAD;id")


# --- Services ---------------------------------------------------------------------------


def _form(**overrides: Any) -> docker_stacks.StackForm:
    values: dict[str, Any] = {
        "name": "shop",
        "source": StackSource.GIT,
        "git_url": "git@github.com:acme/shop.git",
    }
    values.update(overrides)
    return docker_stacks.StackForm(**values)


def test_a_generated_deploy_key_is_stored_encrypted_and_only_its_public_half_kept() -> None:
    form = _form(git_ssh_key=docker_stacks.GENERATE_KEY)
    assert form.validate() == []
    stack = DockerStack(name="shop")
    form.apply(stack)

    assert stack.git_ssh_public_key is not None
    assert stack.git_ssh_public_key.startswith("ssh-ed25519 ")
    assert stack.git_ssh_public_key.endswith(" debcontrol-shop")
    assert stack.git_ssh_key_encrypted is not None
    private = decrypt_secret(stack.git_ssh_key_encrypted)
    assert private.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert private.encode() not in stack.git_ssh_key_encrypted
    source = docker_stacks.git_source(stack)
    assert source.ssh_key == private and source.token == ""


def test_a_pasted_key_is_checked() -> None:
    private, _public = docker_stacks.generate_ssh_key("me")
    assert _form(git_ssh_key=private).validate() == []
    assert _form(git_ssh_key="not a key").validate() == [
        "docker.stack.error.git_ssh_key_invalid"
    ]
    assert _form().validate() == ["docker.stack.error.git_ssh_key_missing"]
    # A key kept from before counts.
    stored = DockerStack(name="shop", git_ssh_key_encrypted=encrypt_secret(private))
    assert _form().validate(stored) == []
    assert _form(git_ssh_key="").validate(stored) == ["docker.stack.error.git_ssh_key_missing"]


def test_form_checks_overrides_known_hosts_and_gate() -> None:
    form = _form(
        git_url="https://github.com/acme/shop.git",
        git_compose_overrides=[" prod.yaml ", "", "./x/y.yml"],
        git_known_hosts=f"# c\n{KNOWN}\n",
        vulnerability_gate="high",
    )
    assert form.validate() == []
    assert form.git_compose_overrides == ["prod.yaml", "x/y.yml"]
    assert form.git_known_hosts == KNOWN
    errors = _form(
        git_url="https://github.com/acme/shop.git",
        git_compose_overrides=["../etc/passwd"],
        git_known_hosts="nope",
        vulnerability_gate="maybe",
    ).validate()
    assert errors == [
        "docker.stack.error.git_overrides",
        "docker.stack.error.git_known_hosts",
        "docker.stack.error.gate",
    ]


def test_moving_to_another_host_forgets_the_pinned_host_key() -> None:
    stack = DockerStack(
        name="shop", source=StackSource.GIT, git_url="git@github.com:acme/shop.git",
        git_known_hosts=KNOWN, git_ssh_key_encrypted=encrypt_secret("k"),
    )
    same = _form(git_url="ssh://git@github.com/acme/other.git")
    assert same.validate(stack) == []
    same.apply(stack)
    assert stack.git_known_hosts == KNOWN
    moved = _form(git_url="git@gitlab.com:acme/shop.git")
    assert moved.validate(stack) == []
    moved.apply(stack)
    assert stack.git_known_hosts is None
    # Back to the editor: every Git setting goes.
    editor = docker_stacks.StackForm(name="shop", source=StackSource.EDITOR, compose=COMPOSE)
    assert editor.validate(stack) == []
    editor.apply(stack)
    assert stack.git_ssh_key_encrypted is None and stack.git_url is None


def test_the_content_hash_of_a_stack_without_overrides_is_unchanged() -> None:
    stack = DockerStack(
        name="shop", source=StackSource.GIT, git_url="https://g.example/x.git",
        git_branch="main", git_compose_path="compose.yaml",
    )
    before = docker_stacks.content_hash(stack)
    stack.git_compose_overrides = []
    assert docker_stacks.content_hash(stack) == before
    stack.git_compose_overrides = ["prod.yaml"]
    assert docker_stacks.content_hash(stack) != before


def test_env_changes_name_variables_never_values() -> None:
    changes = docker_stacks.env_changes(
        "A=1\nB=secret-old\n# C=x\nexport D=4\n", "B=secret-new\nD=4\nE=5\n"
    )
    assert changes == ["+ E", "- A", "~ B"]
    assert "secret" not in "\n".join(changes)


def test_the_compose_diff_compares_with_what_was_deployed() -> None:
    stack = DockerStack(
        name="shop", source=StackSource.EDITOR, compose_content=COMPOSE_V2,
        env_encrypted=encrypt_secret("TOKEN=new"),
    )
    assert docker_stacks.compose_diff(stack).startswith("Not deployed yet")
    stack.deployed_hash = "x"
    assert "not known" in docker_stacks.compose_diff(stack)
    stack.deployed_compose = COMPOSE
    stack.deployed_env_encrypted = encrypt_secret("TOKEN=old")
    diff = docker_stacks.compose_diff(stack)
    assert "-    image: nginx:1.27" in diff and "+    image: nginx:1.28" in diff
    assert "~ TOKEN" in diff and "old" not in diff.replace("(deployed)", "")


def test_the_previous_version_is_known_only_when_it_was_recorded() -> None:
    stack = DockerStack(name="shop", source=StackSource.EDITOR, compose_content=COMPOSE_V2)
    assert docker_stacks.previous_files(stack) is None  # never deployed
    stack.deployed_hash = "x"
    assert docker_stacks.previous_files(stack) is None  # deployed before 0.124.0
    stack.deployed_compose = COMPOSE
    previous = docker_stacks.previous_files(stack)
    assert previous is not None and previous.compose == COMPOSE
    git = DockerStack(
        name="shop", source=StackSource.GIT, git_url="https://g.example/x.git",
        deployed_hash="x",
    )
    assert docker_stacks.previous_files(git) is None  # no commit known
    git.deployed_commit = COMMIT
    previous = docker_stacks.previous_files(git)
    assert previous is not None and previous.git is not None
    assert previous.git.commit == COMMIT


async def test_history_keeps_the_last_versions_only(db_session_factory: Factory) -> None:
    machine = _machine()
    stack = _stack(machine, keep_history=True)
    await _add(db_session_factory, machine, stack)

    async with db_session_factory() as db:
        row = await db.get(DockerStack, stack.id)
        assert row is not None
        for _ in range(docker_stacks.HISTORY_LIMIT + 3):
            await docker_stacks.record_deployed(db, row, commit=None, deployed_by="admin")
            await db.commit()
        versions = await docker_stacks.list_versions(db, stack.id)
        total = (await db.execute(select(DockerStackVersion))).scalars().all()
    assert len(versions) == len(total) == docker_stacks.HISTORY_LIMIT
    assert versions[0].compose_content == COMPOSE
    assert versions[0].deployed_by == "admin"


async def test_without_history_nothing_is_kept(db_session_factory: Factory) -> None:
    machine = _machine()
    stack = _stack(machine)
    await _add(db_session_factory, machine, stack)

    async with db_session_factory() as db:
        row = await db.get(DockerStack, stack.id)
        assert row is not None
        await docker_stacks.record_deployed(db, row, commit=None, deployed_by="admin")
        await db.commit()
        assert row.deployed_compose == COMPOSE
        assert await docker_stacks.list_versions(db, stack.id) == []


def test_rolling_a_git_stack_back_turns_auto_sync_off() -> None:
    stack = DockerStack(
        name="shop", source=StackSource.GIT, git_url="https://g.example/x.git",
        git_branch="main", git_compose_path="compose.yaml", auto_sync=True,
    )
    version = DockerStackVersion(
        source=StackSource.GIT, git_url="https://g.example/x.git", git_branch="release",
        git_compose_path="c.yaml", commit=COMMIT, env_encrypted=encrypt_secret("A=1"),
    )

    assert docker_stacks.restore_version(stack, version) == COMMIT
    assert stack.auto_sync is False
    assert (stack.git_branch, stack.git_compose_path) == ("release", "c.yaml")
    assert docker_stacks.env_text(stack) == "A=1"


# --- Jobs ----------------------------------------------------------------------------------


async def test_the_gate_stops_a_stack_deploy_and_puts_everything_back(
    db_session_factory: Factory, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _stack(
        machine, compose_content=COMPOSE_V2, vulnerability_gate="critical",
        deployed_hash="old", deployed_compose=COMPOSE,
    )
    job = _job(machine, DockerJobKind.STACK_DEPLOY, "shop", ref_id=stack.id)
    await _add(db_session_factory, machine, stack, job)
    machine_shell.finishes(
        f"@@DC_OLD nginx:1.27 {OLD_ID}\n@@DC_NEW nginx:1.27 {NEW_ID}\n@@DC_PREPARED\n"
    )
    machine_shell.finishes(_scan_lines("nginx:1.27", ["CVE-2024-0001:CRITICAL"]))
    machine_shell.finishes("@@DC_ROLLED_BACK\n@@DC_DONE\n")

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    row = await _get(db_session_factory, DockerStack, stack.id)
    assert stored.status == DockerJobStatus.BLOCKED
    assert stored.error.startswith("Stopped by the vulnerability gate (critical): nginx:1.27")
    assert stored.result["stack_gate"]["nginx:1.27"]["allowed"] is False
    assert [remote for remote, _ in machine_shell.started] == [
        tasks.remote_id(job.id, phase) for phase in ("prepare", "scan", "restore")
    ]
    prepare, _scan, restore = (script for _, script in machine_shell.started)
    assert "@@DC_PREPARED" in prepare and "dc up" not in prepare
    assert f"$D tag {OLD_ID} nginx:1.27" in restore
    assert COMPOSE in restore  # the previous compose file goes back
    assert row.last_status == "blocked" and row.deployed_hash == "old"
    assert [e for e, _ in machine_shell.notified] == [NotificationEventType.DOCKER_STACK_FAILED]


async def test_a_stack_deploy_the_gate_allows_goes_up_and_is_kept_in_history(
    db_session_factory: Factory, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _stack(machine, vulnerability_gate="high", keep_history=True)
    job = _job(machine, DockerJobKind.STACK_DEPLOY, "shop", ref_id=stack.id)
    await _add(db_session_factory, machine, stack, job)
    machine_shell.finishes(f"@@DC_NEW nginx:1.27 {NEW_ID}\n@@DC_PREPARED\n")
    machine_shell.finishes(_scan_lines("nginx:1.27", ["CVE-2024-0002:MEDIUM"]))
    machine_shell.finishes("@@DC_DONE\n")

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SUCCEEDED, stored.error
    assert stored.result["stack_gate"]["nginx:1.27"]["allowed"] is True
    assert [remote for remote, _ in machine_shell.started] == [
        tasks.remote_id(job.id, phase) for phase in ("prepare", "scan", "up")
    ]
    async with db_session_factory() as db:
        [version] = (await db.execute(select(DockerStackVersion))).scalars().all()
    assert version.stack_id == stack.id and version.deployed_by == "admin"


async def test_images_already_running_are_not_scanned_again(
    db_session_factory: Factory, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _stack(machine, vulnerability_gate="critical")
    job = _job(machine, DockerJobKind.STACK_DEPLOY, "shop", ref_id=stack.id)
    await _add(db_session_factory, machine, stack, job)
    machine_shell.finishes(
        f"@@DC_OLD nginx:1.27 {OLD_ID}\n@@DC_NEW nginx:1.27 {OLD_ID}\n@@DC_PREPARED\n"
    )
    machine_shell.finishes("@@DC_DONE\n")

    await tasks._run_docker_job(str(job.id))

    assert (await _get(db_session_factory, DockerJob, job.id)).status == DockerJobStatus.SUCCEEDED
    assert [remote for remote, _ in machine_shell.started] == [
        tasks.remote_id(job.id, phase) for phase in ("prepare", "up")
    ]


async def test_an_automatic_rollback_is_reported(
    db_session_factory: Factory, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _stack(
        machine, compose_content=COMPOSE_V2, auto_rollback=True,
        deployed_hash="old", deployed_compose=COMPOSE,
    )
    job = _job(machine, DockerJobKind.STACK_DEPLOY, "shop", ref_id=stack.id)
    await _add(db_session_factory, machine, stack, job)
    machine_shell.finishes(
        "@@DC_STEP health\n@@DC_STEP rollback\n@@DC_ROLLED_BACK\n@@DC_FAILED health\n", 1
    )

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    [(_remote, script)] = machine_shell.started
    assert "dc_healthy" in script and COMPOSE in script
    assert stored.status == DockerJobStatus.FAILED
    assert stored.result["rolled_back"] is True
    assert "the previous version was put back" in stored.error
    assert (await _get(db_session_factory, DockerStack, stack.id)).deployed_hash == "old"


async def test_a_check_job_changes_nothing_and_reports_its_result(
    db_session_factory: Factory, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _stack(machine, compose_content=COMPOSE_V2, deployed_hash="x",
                   deployed_compose=COMPOSE)
    ok = _job(machine, DockerJobKind.STACK_CHECK, "shop", ref_id=stack.id)
    await _add(db_session_factory, machine, stack, ok)
    machine_shell.finishes("@@DC_STEP config\n@@DC_CHECK_OK\n")

    await tasks._run_docker_job(str(ok.id))

    [(_remote, script)] = machine_shell.started
    assert "+    image: nginx:1.28" in script
    assert (await _get(db_session_factory, DockerJob, ok.id)).status == DockerJobStatus.SUCCEEDED
    failed = _job(machine, DockerJobKind.STACK_CHECK, "shop", ref_id=stack.id)
    await _add(db_session_factory, failed)
    machine_shell.finishes("@@DC_FAILED config\n", 1)
    await tasks._run_docker_job(str(failed.id))
    stored = await _get(db_session_factory, DockerJob, failed.id)
    assert stored.status == DockerJobStatus.FAILED
    assert 'step "config"' in stored.error
    assert machine_shell.notified == []


async def test_the_host_key_seen_first_is_pinned(
    db_session_factory: Factory, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _stack(
        machine, source=StackSource.GIT, compose_content=None,
        git_url="git@github.com:acme/shop.git", git_branch="main",
        git_compose_path="compose.yaml",
        git_ssh_key_encrypted=encrypt_secret(docker_stacks.generate_ssh_key("x")[0]),
    )
    job = _job(machine, DockerJobKind.STACK_DEPLOY, "shop", ref_id=stack.id)
    await _add(db_session_factory, machine, stack, job)
    machine_shell.finishes(f"@@DC_HOSTKEY {KNOWN}\n@@DC_COMMIT {COMMIT}\n@@DC_DONE\n")

    await tasks._run_docker_job(str(job.id))

    row = await _get(db_session_factory, DockerStack, stack.id)
    assert row.git_known_hosts == KNOWN
    assert row.deployed_commit == COMMIT


async def test_auto_sync_does_not_retry_a_commit_that_failed(
    db_session_factory: Factory, machine_shell: FakeMachine, celery_calls: Any
) -> None:
    machine = _machine()
    stack = _stack(
        machine, source=StackSource.GIT, compose_content=None,
        git_url="https://git.example.com/me/shop.git", git_branch="main",
        git_compose_path="compose.yaml", deployed_commit=COMMIT, auto_sync=True,
    )
    stack.deployed_hash = docker_stacks.content_hash(stack)
    failed = _job(
        machine, DockerJobKind.STACK_DEPLOY, "shop", ref_id=stack.id,
        status=DockerJobStatus.FAILED, result={"commit": NEW_COMMIT, "rolled_back": True},
    )
    await _add(db_session_factory, machine, stack, failed)
    machine_shell.answer("ls-remote", f"@@DC_COMMIT {NEW_COMMIT}\n")

    result = await tasks._sync_git_stack(str(stack.id), started_by="Git auto-sync")

    assert result == {"ok": True, "deployed": False, "commit": NEW_COMMIT}
    async with db_session_factory() as db:
        assert len((await db.execute(select(DockerJob))).scalars().all()) == 1


# --- Web and REST API ------------------------------------------------------------------------


async def _versioned_stack(
    db_session_factory: Factory, machine_id: uuid.UUID, *, source: str = StackSource.EDITOR
) -> tuple[uuid.UUID, uuid.UUID]:
    async with db_session_factory() as db:
        stack = DockerStack(
            machine_id=machine_id, name="site", source=source, compose_content=COMPOSE_V2,
            keep_history=True, created_by="admin",
        )
        if source == StackSource.GIT:
            stack.git_url = "https://git.example.test/ops/site.git"
            stack.git_branch = "main"
            stack.git_compose_path = "compose.yaml"
            stack.auto_sync = True
        db.add(stack)
        await db.flush()
        version = DockerStackVersion(
            stack_id=stack.id, source=source, compose_content=COMPOSE,
            env_encrypted=encrypt_secret("TOKEN=old-secret"),
            git_url=stack.git_url, git_branch=stack.git_branch,
            git_compose_path=stack.git_compose_path,
            commit=COMMIT if source == StackSource.GIT else None, content_hash="h",
            deployed_by="admin",
        )
        db.add(version)
        await db.commit()
        return stack.id, version.id


async def test_rolling_back_from_the_web_restores_and_deploys(
    client: Any, db_session_factory: Factory, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, version_id = await _versioned_stack(
        db_session_factory, machine_id, source=StackSource.GIT
    )
    csrf = await csrf_token(client, machine_id)
    url = f"/machines/{machine_id}/docker/stacks/{stack_id}"

    page = await client.get(url)
    shown = await client.get(f"{url}/versions/{version_id}")
    response = await client.post(f"{url}/versions/{version_id}/rollback",
                                 data={"csrf_token": csrf})

    assert page.status_code == 200 and f"versions/{version_id}" in page.text
    assert shown.status_code == 200 and "old-secret" not in shown.text
    assert response.status_code == 303
    [job] = await jobs_of(db_session_factory, machine_id)
    assert job.kind == DockerJobKind.STACK_DEPLOY and (job.params or {})["commit"] == COMMIT
    async with db_session_factory() as db:
        stack = await db.get(DockerStack, stack_id)
        assert stack is not None and stack.auto_sync is False
        assert docker_stacks.env_text(stack) == "TOKEN=old-secret"
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.rollback")
    assert (entry.details or {})["auto_sync_turned_off"] is True


@pytest.mark.parametrize(
    "permission",
    [Permission.ACTION_UPDATES, Permission.ACTION_TERMINAL],
    ids=["updates", "terminal"],
)
async def test_rolling_back_needs_terminal_and_updates(
    client: Any, login_as: Any, db_session_factory: Factory, celery_calls: Any, permission: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, version_id = await _versioned_stack(db_session_factory, machine_id)
    url = f"/machines/{machine_id}/docker/stacks/{stack_id}/versions/{version_id}"
    await login_as(client, permissions={Permission.MACHINE_VIEW, permission})
    csrf = await csrf_token(client, machine_id)

    response = await client.post(f"{url}/rollback", data={"csrf_token": csrf})

    assert response.status_code == 403
    if permission == Permission.ACTION_UPDATES:
        assert (await client.get(url)).status_code == 403
    assert celery_calls == []


async def test_the_check_needs_terminal_and_its_output_stays_with_it(
    client: Any, login_as: Any, db_session_factory: Factory, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await _versioned_stack(db_session_factory, machine_id)
    base_url = f"/machines/{machine_id}/docker"
    csrf = await csrf_token(client, machine_id)

    response = await client.post(f"{base_url}/stacks/{stack_id}/check",
                                 data={"csrf_token": csrf})

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303 and job.kind == DockerJobKind.STACK_CHECK
    async with db_session_factory() as db:
        row = await db.get(DockerJob, job.id)
        assert row is not None
        row.output = "+    image: private-registry/secret-app:1"
        await db.commit()
    assert "secret-app" in (await client.get(f"{base_url}/jobs/{job.id}")).text
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_UPDATES})
    viewer = await client.get(f"{base_url}/jobs/{job.id}")
    assert viewer.status_code == 200 and "secret-app" not in viewer.text
    csrf = await csrf_token(client, machine_id)
    denied = await client.post(f"{base_url}/stacks/{stack_id}/check", data={"csrf_token": csrf})
    assert denied.status_code == 403


async def test_api_deploy_key_versions_check_and_rollback(
    client: Any, login_as: Any, db_session_factory: Factory
) -> None:
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    created = await create_stack(
        client, machine_id, headers, source="git", compose="",
        git_url="git@github.com:acme/shop.git", git_ssh_key="generate",
        git_compose_overrides=["prod.yaml"], keep_history=True, auto_rollback=True,
        vulnerability_gate="critical",
    )
    assert created.status_code == 201, created.text
    stack = created.json()["stack"]
    assert stack["git_ssh_public_key"].startswith("ssh-ed25519 ")
    assert "PRIVATE KEY" not in created.text
    assert (stack["keep_history"], stack["auto_rollback"], stack["vulnerability_gate"]) == (
        True, True, "critical"
    )
    assert stack["git_compose_overrides"] == ["prod.yaml"]
    url = f"{base(machine_id)}/stacks/{stack['id']}"

    # None keeps the key.
    kept = await client.put(url, json={"source": "git",
                                       "git_url": "git@github.com:acme/shop.git"},
                            headers=headers)
    assert kept.status_code == 200, kept.text
    assert kept.json()["stack"]["git_ssh_public_key"] == stack["git_ssh_public_key"]

    check = await client.post(f"{url}/check", headers=headers)
    assert check.status_code == 202, check.text
    assert check.json()["job"]["kind"] == "stack_check"
    assert ("machine.docker.stack.check", "success") in await audit_actions(db_session_factory)
    assert (await client.get(f"{url}/versions", headers=headers)).json() == []

    async with db_session_factory() as db:
        await db.execute(delete(DockerJob))
        version = DockerStackVersion(
            stack_id=uuid.UUID(stack["id"]), source="git",
            git_url="git@github.com:acme/shop.git", git_branch="main",
            git_compose_path="compose.yaml", commit=COMMIT, content_hash="h",
        )
        db.add(version)
        await db.commit()
        version_id = version.id
    listed = await client.get(f"{url}/versions", headers=headers)
    assert [v["id"] for v in listed.json()] == [str(version_id)]
    viewer = await headers_for(client, login_as, {Permission.MACHINE_VIEW})
    assert (await client.get(f"{url}/versions", headers=viewer)).status_code == 200
    assert (await client.get(f"{url}/versions/{version_id}", headers=viewer)).status_code == 403
    assert (await client.post(f"{url}/check", headers=viewer)).status_code == 403
    rollback = await client.post(f"{url}/versions/{version_id}/rollback", headers=headers)
    assert rollback.status_code == 202, rollback.text
    assert rollback.json()["job"]["params"]["commit"] == COMMIT
    busy = await client.post(f"{url}/versions/{version_id}/rollback", headers=headers)
    assert busy.status_code == 409
    missing = await client.post(f"{url}/versions/{uuid.uuid4()}/rollback", headers=headers)
    assert missing.status_code == 404


async def test_api_refuses_an_ssh_repository_without_a_key(
    client: Any, db_session_factory: Any
) -> None:
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    response = await create_stack(
        client, machine_id, headers, source="git", compose="",
        git_url="git@github.com:acme/shop.git",
    )

    assert response.status_code == 422
    assert response.json()["detail"] == ["docker.stack.error.git_ssh_key_missing"]
