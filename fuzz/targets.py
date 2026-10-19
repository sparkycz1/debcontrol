"""The fuzz targets. Each takes raw bytes and feeds them to one parser or
guard the way untrusted input would reach it, then checks the contract:

- a parser of machine output (`app.ssh.*`) or of a network reply never
  raises — a hostile or broken machine must not be able to crash a sweep;
- a guard that rejects input does so with the documented `ValueError` (or
  YAML error), never anything else;
- whatever a security guard lets through really has the property it
  promises (`safe_local_path` returns a same-site path, `redact_url` keeps
  no path or query, `normalize_email` returns something email-shaped).

Plain Python on purpose: `fuzz.run` drives these under Atheris, and
`tests/test_fuzz_targets.py` runs them on every OS over a seed corpus.
"""

from __future__ import annotations

import contextlib
import posixpath
from collections.abc import Callable

import yaml

from app.auth.session_policy import parse_networks
from app.schemas.user import normalize_email
from app.services.docker_backups import form_from_definition, parse_import
from app.services.endpoint_checks import parse_tls_target
from app.services.machine_tags import parse_tag_names_from_text
from app.services.network_probes import parse_dns_answers
from app.services.push_channels import redact_url
from app.ssh import docker_compose, docker_files, docker_prune, restic
from app.ssh.docker_cli import DockerAccessError, DockerCommandError, parse_wrapped
from app.ssh.docker_inventory import parse_inventory
from app.ssh.docker_scan import parse_scan_output
from app.ssh.docker_update import (
    parse_plan_output,
    parse_pull_output,
    parse_recreate_output,
    plan_from_inspect,
)
from app.ssh.facts import parse_facts_output
from app.ssh.image_updates import ImageCheckError, parse_image_update_output
from app.ssh.logs import (
    JOURNAL_PRIORITIES,
    MAX_BOOT_OFFSET,
    is_path_allowed,
    normalize_boot,
    normalize_priority,
    normalize_unit,
    parse_directory_listing,
    parse_journal_json,
)
from app.ssh.monitoring import parse_monitoring_output
from app.ssh.packages import parse_packages_output
from app.ssh.proxmox import (
    parse_backups,
    parse_cluster,
    parse_failed_tasks,
    parse_guests,
    parse_pve_version,
    parse_storage,
    parse_zfs_pools,
)
from app.ssh.readiness import parse_readiness_output
from app.ssh.security_advisories import parse_changelog, parse_source_map
from app.ssh.services import parse_services_output
from app.web.redirects import safe_local_path
from app.web.routes.notifications import _parse_conditions_yaml_block


def _text(data: bytes) -> str:
    # asyncssh hands command output over decoded the same lenient way.
    return data.decode("utf-8", errors="replace")


def _sections(data: bytes, count: int) -> list[str]:
    parts = _text(data).split("\x00")
    return (parts + [""] * count)[:count]


def facts(data: bytes) -> None:
    parse_facts_output(_text(data))


def packages(data: bytes) -> None:
    parse_packages_output(_text(data))


def services(data: bytes) -> None:
    parse_services_output(_text(data))


def monitoring(data: bytes) -> None:
    text = _text(data)
    parse_monitoring_output(text, is_physical=False)
    parse_monitoring_output(text, is_physical=True)


def journal(data: bytes) -> None:
    parse_journal_json(_text(data))


def directory_listing(data: bytes) -> None:
    parse_directory_listing(_text(data))


def image_updates(data: bytes) -> None:
    # The documented "this account can't reach Docker" answer.
    with contextlib.suppress(ImageCheckError):
        parse_image_update_output(_text(data))


def log_path(data: bytes) -> None:
    """The Logs tab's file/directory path — only ever something inside an
    allowed prefix, however it's spelled."""
    path = _text(data)
    if is_path_allowed(path, ["/var/log"]):
        normalized = posixpath.normpath(path)
        assert normalized == "/var/log" or normalized.startswith("/var/log/")


def journal_filters(data: bytes) -> None:
    unit, priority, boot = _sections(data, 3)
    assert normalize_priority(priority) in ("", *JOURNAL_PRIORITIES)
    value = normalize_unit(unit)
    assert value == "" or (len(value) <= 200 and value == value.strip())
    offset = normalize_boot(boot)
    assert offset == "" or -MAX_BOOT_OFFSET <= int(offset) <= 0


def readiness(data: bytes) -> None:
    parse_readiness_output(_text(data))


def advisories(data: bytes) -> None:
    changelog, version = _sections(data, 2)
    parse_source_map(changelog)
    parse_changelog(changelog, version or None)


def proxmox(data: bytes) -> None:
    a, b, c = _sections(data, 3)
    parse_pve_version(a)
    parse_guests(a)
    parse_storage(a)
    parse_cluster(a)
    parse_failed_tasks(a)
    parse_zfs_pools(a, b)
    parse_backups(a, b, c)


def dns_answer(data: bytes) -> None:
    query_id = int.from_bytes(data[:2].ljust(2, b"\x00"), "big")
    with contextlib.suppress(ValueError):
        parse_dns_answers(data, query_id)


def conditions_yaml(data: bytes) -> None:
    try:
        conditions = _parse_conditions_yaml_block(_text(data))
    except (ValueError, yaml.YAMLError):
        return
    assert isinstance(conditions, list)


def redirect(data: bytes) -> None:
    result = safe_local_path(_text(data), "/dashboard")
    assert result.startswith("/")
    assert not result.startswith("//")
    assert "\\" not in result
    assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in result)


def webhook_redaction(data: bytes) -> None:
    url = _text(data)
    redacted = redact_url(url)
    assert "?" not in redacted
    assert redacted == "…" or redacted.count("/") <= 3


def email(data: bytes) -> None:
    try:
        result = normalize_email(_text(data))
    except ValueError:
        return
    if result is not None:
        local, _, domain = result.partition("@")
        assert local and "." in domain and not any(ch.isspace() for ch in result)


def networks(data: bytes) -> None:
    parse_networks(_text(data))


def tls_target(data: bytes) -> None:
    try:
        host, port = parse_tls_target(_text(data))
    except ValueError:
        return
    assert isinstance(host, str) and isinstance(port, int)


def tags(data: bytes) -> None:
    for name in parse_tag_names_from_text(_text(data)):
        assert name and name == name.strip()


def docker_inventory(data: bytes) -> None:
    text = _text(data)
    parse_inventory(text)
    # The documented "this account can't reach Docker" answer.
    with contextlib.suppress(DockerAccessError):
        parse_wrapped(text)


def docker_scan(data: bytes) -> None:
    parse_scan_output(_text(data))


def docker_update(data: bytes) -> None:
    """Pull/recreate answers never raise; an inspect answer either fails with
    the documented error or yields a plan without crashing."""
    text = _text(data)
    parse_pull_output(text)
    parse_recreate_output(text)
    try:
        container, image = parse_plan_output(text)
    except DockerCommandError:
        return
    with contextlib.suppress(DockerCommandError):
        plan_from_inspect(container, image)


def docker_files_listing(data: bytes) -> None:
    """The file browser's listing and tar parsing never raise; a path the
    guard accepts is absolute with no `..` left in it."""
    text = _text(data)
    docker_files.parse_listing(text)
    docker_files.first_file(data)
    docker_files.first_member_owner(data)
    try:
        path = docker_files.normalize_path(text)
    except DockerCommandError:
        return
    assert path.startswith("/") and not path.startswith("//")
    assert ".." not in path.split("/")


def docker_prune_output(data: bytes) -> None:
    text = _text(data)
    assert docker_prune.parse_reclaimed_bytes(text) >= 0
    assert all(v >= 0 for v in docker_prune.parse_removed_counts(text).values())


def restic_output(data: bytes) -> None:
    """restic's answers never raise; a host path the guard accepts is
    absolute and normalized; env lines fail only with the documented error."""
    text = _text(data)
    restic.parse_snapshots(text)
    restic.parse_backup_summary(text)
    restic.failed_step(text)
    path = restic.normalize_host_path(text)
    if path is not None:
        assert path.startswith("/") and ".." not in path.split("/")
    inside = restic.normalize_snapshot_path(text)
    if inside is not None:
        assert inside.startswith("/") and ".." not in inside.split("/") and ":" not in inside
    with contextlib.suppress(DockerCommandError):
        restic.parse_env_lines(text)


def compose_input(data: bytes) -> None:
    """A compose path the guard accepts stays inside the repository; a Git
    URL it accepts is plain https with no credentials."""
    text = _text(data)
    docker_compose.parse_commit(text)
    docker_compose.failed_step(text)
    path = docker_compose.normalize_compose_path(text)
    if path is not None:
        # "..." or "..hidden" are file names, not the parent directory.
        assert not path.startswith("/") and ".." not in path.split("/")
    if docker_compose.is_git_url_valid(text):
        assert text.startswith("https://") and not any(ch.isspace() for ch in text)
    directory = docker_compose.normalize_stack_directory(text)
    if directory:
        # Absolute (or ~/...), no "..", never a system directory or "/" itself.
        assert directory.startswith(("/", "~/")) and ".." not in directory.split("/")
        assert directory not in ("/", "/etc", "/usr") and not directory.startswith("/etc/")
        assert docker_compose.stack_dir_shell("x", directory)


def backup_import(data: bytes) -> None:
    """An uploaded backups export either parses into definitions that
    fill in the form, or raises ValueError — nothing else."""
    try:
        definitions = parse_import(_text(data))
    except ValueError:
        return
    assert definitions
    for definition in definitions:
        form_from_definition(definition)


TARGETS: dict[str, Callable[[bytes], None]] = {
    fn.__name__: fn
    for fn in (
        facts,
        packages,
        services,
        monitoring,
        journal,
        directory_listing,
        image_updates,
        log_path,
        journal_filters,
        readiness,
        advisories,
        proxmox,
        dns_answer,
        conditions_yaml,
        redirect,
        webhook_redaction,
        email,
        networks,
        tls_target,
        tags,
        docker_inventory,
        docker_scan,
        docker_update,
        docker_files_listing,
        docker_prune_output,
        restic_output,
        compose_input,
        backup_import,
    )
}
