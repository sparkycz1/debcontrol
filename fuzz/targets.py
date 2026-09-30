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
from app.services.endpoint_checks import parse_tls_target
from app.services.machine_tags import parse_tag_names_from_text
from app.services.network_probes import parse_dns_answers
from app.services.push_channels import redact_url
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
    )
}
