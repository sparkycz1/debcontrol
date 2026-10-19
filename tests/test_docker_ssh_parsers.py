"""Reading back what Docker, Compose, Trivy, Grype and restic print on a
machine (`app.ssh.docker_*`, `app.ssh.restic`): realistic output becomes
the right structure, and empty or garbled output never raises."""

from __future__ import annotations

import io
import json
import tarfile
from typing import Any

import pytest

from app.ssh import docker_compose, restic
from app.ssh.docker_cli import (
    DOCKER_NO_ACCESS_MARKER,
    EXIT_MARKER,
    DockerAccessError,
    DockerCommandError,
    parse_wrapped,
)
from app.ssh.docker_files import build_tar, first_file, first_member_owner, parse_listing
from app.ssh.docker_inventory import parse_container, parse_inventory, split_sections
from app.ssh.docker_prune import parse_reclaimed_bytes, parse_removed_counts
from app.ssh.docker_scan import merge, normalize_severity, parse_scan_output
from app.ssh.docker_update import (
    parse_plan_output,
    parse_pull_output,
    parse_recreate_output,
    plan_from_inspect,
)

_OLD = "sha256:" + "1" * 64
_NEW = "sha256:" + "2" * 64
_SHA = "0123456789abcdef0123456789abcdef01234567"

# Garbage every parser below must survive.
_GARBAGE = ["", "\n\n", "{not json", "[1, 2", "null", "\x00\xff", "@@DC_", "V\t\t\t", "[[[[" * 50]


# --- Wrapped scripts ---------------------------------------------------------


def test_wrapped_output_splits_off_the_exit_status() -> None:
    result = parse_wrapped(f"line one\nline two\n{EXIT_MARKER}3\n")

    assert result.exit_status == 3
    assert result.output == "line one\nline two"


def test_wrapped_output_without_a_readable_status() -> None:
    assert parse_wrapped("partial output").exit_status is None
    assert parse_wrapped(f"x\n{EXIT_MARKER}abc").exit_status is None
    assert parse_wrapped("").output == ""


def test_the_no_access_answer_raises() -> None:
    with pytest.raises(DockerAccessError):
        parse_wrapped(f"{DOCKER_NO_ACCESS_MARKER}\n")


# --- Inventory ---------------------------------------------------------------


def _inspect_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "Id": "c" * 64,
        "Name": "/immich_server",
        "Image": _OLD,
        "Created": "2026-10-01T10:00:00Z",
        "RestartCount": 2,
        "State": {
            "Status": "running",
            "Running": True,
            "StartedAt": "2026-10-01T10:00:05Z",
            "ExitCode": 0,
            "Health": {"Status": "healthy"},
        },
        "Config": {
            "Image": "ghcr.io/immich-app/immich-server:release",
            "Env": ["DB_PASSWORD=hunter2", "TZ=Europe/Prague", "PATH=/usr/bin"],
            "Cmd": ["start.sh", "--port", "2283"],
            "Labels": {
                "com.docker.compose.project": "immich",
                "com.docker.compose.service": "immich-server",
                "com.docker.compose.project.working_dir": "/opt/immich",
                "com.docker.compose.project.config_files": (
                    "/opt/immich/compose.yml,/opt/immich/override.yml"
                ),
            },
        },
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "immich_default",
            "RestartPolicy": {"Name": "unless-stopped"},
        },
        "NetworkSettings": {
            "Networks": {"immich_default": {}},
            "Ports": {
                "2283/tcp": [{"HostIp": "0.0.0.0", "HostPort": "2283"}],  # noqa: S104
                "9000/tcp": None,
            },
        },
        "Mounts": [
            {"Type": "volume", "Name": "immich_upload", "Source": "/var/lib/docker/volumes/x",
             "Destination": "/usr/src/app/upload", "RW": True},
            {"Type": "bind", "Source": "/etc/localtime", "Destination": "/etc/localtime",
             "RW": False},
        ],
    }
    row.update(overrides)
    return row


def test_a_container_is_reduced_to_what_the_pages_show() -> None:
    container = parse_container(_inspect_row())

    assert container is not None
    assert container["name"] == "immich_server"
    assert container["running"] is True
    assert container["health"] == "healthy"
    assert container["restart_policy"] == "unless-stopped"
    assert container["restart_count"] == 2
    assert container["command"] == "start.sh --port 2283"
    assert sorted(container["ports"]) == ["0.0.0.0:2283->2283/tcp", "9000/tcp"]
    assert container["networks"] == ["immich_default"]
    assert container["compose_project"] == "immich"
    assert container["compose_config_files"] == [
        "/opt/immich/compose.yml",
        "/opt/immich/override.yml",
    ]
    assert [m["rw"] for m in container["mounts"]] == [True, False]


def test_environment_values_never_leave_the_machine() -> None:
    container = parse_container(_inspect_row())

    assert container is not None
    assert container["env_names"] == ["DB_PASSWORD", "PATH", "TZ"]
    assert "hunter2" not in json.dumps(container)


def test_a_container_record_of_the_wrong_shape_does_not_raise() -> None:
    assert parse_container({}) is None
    odd = parse_container(
        {"Name": "/x", "Config": "nope", "State": [], "Mounts": ["bad"],
         "NetworkSettings": {"Ports": {"80/tcp": "bad"}}}
    )
    assert odd is not None
    assert (odd["mounts"], odd["ports"], odd["exit_code"]) == ([], [], None)


def _inventory_output() -> str:
    images = [
        {"ID": _OLD, "Repository": "ghcr.io/immich-app/immich-server", "Tag": "release",
         "Digest": "<none>", "Size": "1.2GB", "CreatedAt": "2026-09-30"},
        {"ID": _NEW, "Repository": "<none>", "Tag": "<none>", "Digest": "<none>",
         "Size": "512MB", "CreatedAt": "2026-09-01"},
    ]
    volumes = [
        {"Name": "immich_upload", "Driver": "local",
         "Labels": "com.docker.compose.project=immich,com.docker.compose.volume=upload"},
        {"Name": "e" * 64, "Driver": "local", "Labels": ""},
    ]
    sizes = [{"Name": "immich_upload", "Size": "10GB", "Links": 1}]
    networks = [
        {"ID": "n1", "Name": "immich_default", "Driver": "bridge", "Scope": "local",
         "Internal": "false"},
        {"ID": "n0", "Name": "bridge", "Driver": "bridge", "Scope": "local", "Internal": "false"},
    ]
    compose = [{"Name": "immich", "Status": "running(1)",
                "ConfigFiles": "/opt/immich/compose.yml, /opt/immich/override.yml"}]
    df = [
        {"Type": "Images", "TotalCount": "2", "Active": "1", "Size": "1.7GB",
         "Reclaimable": "512MB (29%)"},
        {"Type": "Local Volumes", "TotalCount": "2", "Active": "1", "Size": "10GB",
         "Reclaimable": "0B (0%)"},
        {"Type": "Something New", "TotalCount": "1"},
    ]
    return "\n".join(
        [
            "===VERSION===",
            "27.3.1",
            "===IMAGES===",
            *(json.dumps(i) for i in images),
            "WARNING: not json",
            "===INSPECT===",
            json.dumps([_inspect_row()]),
            "===VOLUMES===",
            *(json.dumps(v) for v in volumes),
            "===VOLUME_SIZES===",
            json.dumps(sizes),
            "===NETWORKS===",
            *(json.dumps(n) for n in networks),
            "===COMPOSE===",
            json.dumps(compose),
            "===DF===",
            *(json.dumps(d) for d in df),
        ]
    )


def test_a_full_inventory_is_parsed_and_cross_referenced() -> None:
    inventory = parse_inventory(_inventory_output())

    assert inventory.version == "27.3.1"
    assert [c["name"] for c in inventory.containers] == ["immich_server"]

    used, dangling = inventory.images
    assert (used["ref"], used["in_use"], used["digest"]) == (
        "ghcr.io/immich-app/immich-server:release", True, "")
    assert (dangling["dangling"], dangling["in_use"], dangling["ref"]) == (True, False, "")
    assert used["size_bytes"] is not None and used["size_bytes"] > dangling["size_bytes"]

    named, anonymous = inventory.volumes
    assert named["name"] == "immich_upload"
    assert (named["used_by"], named["links"], named["compose_project"]) == (
        ["immich_server"], 1, "immich")
    assert named["size_bytes"] is not None
    assert anonymous["anonymous"] is True

    assert [n["name"] for n in inventory.networks] == ["bridge", "immich_default"]
    assert inventory.networks[0]["builtin"] is True
    assert inventory.networks[1]["containers"] == ["immich_server"]

    assert inventory.compose == [
        {"name": "immich", "status": "running(1)",
         "config_files": ["/opt/immich/compose.yml", "/opt/immich/override.yml"]}
    ]
    assert set(inventory.df) == {"images", "volumes"}
    assert inventory.df["images"]["total"] == 2
    assert inventory.df["volumes"]["reclaimable_bytes"] == 0


def test_network_inspect_becomes_details() -> None:
    inspected = [
        {
            "Name": "site_default",
            "Id": "e" * 64,
            "Created": "2026-10-01T10:00:00.123Z",
            "Scope": "local",
            "Driver": "bridge",
            "EnableIPv6": False,
            "IPAM": {
                "Driver": "default",
                "Config": [{"Subnet": "172.18.0.0/16", "Gateway": "172.18.0.1"}],
            },
            "Internal": False,
            "Attachable": True,
            "Containers": {
                "abc": {
                    "Name": "web",
                    "IPv4Address": "172.18.0.2/16",
                    "IPv6Address": "",
                    "MacAddress": "02:42:ac:12:00:02",
                }
            },
            "Options": {"com.docker.network.bridge.name": "br-site"},
            "Labels": {"com.docker.compose.project": "site"},
        },
        {"Name": "host", "Driver": "host", "IPAM": {"Config": None}, "Containers": {}},
        {"Name": ""},
        "garbage",
    ]
    inventory = parse_inventory("===NETWORK_INSPECT===\n" + json.dumps(inspected))

    assert [n["name"] for n in inventory.network_details] == ["host", "site_default"]
    host, site = inventory.network_details
    assert host["builtin"] is True and host["subnets"] == [] and host["containers"] == []
    assert site["subnets"] == [{"subnet": "172.18.0.0/16", "gateway": "172.18.0.1", "ip_range": ""}]
    assert site["attachable"] is True and site["compose_project"] == "site"
    assert site["options"] == {"com.docker.network.bridge.name": "br-site"}
    assert site["containers"] == [
        {"id": "abc", "name": "web", "ipv4": "172.18.0.2/16", "ipv6": "",
         "mac": "02:42:ac:12:00:02"}
    ]


def test_only_the_sections_asked_for_are_filled() -> None:
    inventory = parse_inventory("===VERSION===\n26.0.0\n===NETWORKS===\n")

    assert inventory.version == "26.0.0"
    assert inventory.images == [] and inventory.networks == [] and inventory.df == {}
    sections = split_sections("noise before\n===DF===\n{}\n===BOGUS===\nx")
    assert sections == {"df": "{}\n===BOGUS===\nx"}


@pytest.mark.parametrize("garbage", _GARBAGE)
def test_a_garbled_inventory_is_empty_not_an_error(garbage: str) -> None:
    raw = "\n".join(f"==={name}===\n{garbage}" for name in
                    ("VERSION", "IMAGES", "INSPECT", "VOLUMES", "VOLUME_SIZES", "NETWORKS",
                     "NETWORK_INSPECT", "COMPOSE", "DF"))
    inventory = parse_inventory(raw)

    assert inventory.containers == [] and inventory.images == [] and inventory.compose == []
    assert inventory.network_details == []


# --- Prune -------------------------------------------------------------------

_PRUNE_OUTPUT = """\
@@DC_PRUNE containers
Deleted Containers:
4f1c2d3e4f5a
9a8b7c6d5e4f

Total reclaimed space: 12.5MB
@@DC_PRUNE networks
Deleted Networks:
old_default

@@DC_PRUNE volumes
Total reclaimed space: 0B
@@DC_PRUNE build_cache
Error response from daemon: a prune operation is already running
@@DC_FAILED build_cache
"""


def test_prune_output_counts_what_each_step_removed() -> None:
    counts = parse_removed_counts(_PRUNE_OUTPUT)

    assert counts == {"containers": 2, "networks": 1, "volumes": 0, "build_cache": 0}


def test_prune_reclaimed_space_is_summed_across_steps() -> None:
    raw = "Total reclaimed space: 1.5GB\nTotal reclaimed space: 0B\nTotal reclaimed space: 500MB\n"

    assert parse_reclaimed_bytes(raw) == pytest.approx(2.0e9, rel=0.1)
    assert parse_reclaimed_bytes(_PRUNE_OUTPUT) > 0


@pytest.mark.parametrize("garbage", [*_GARBAGE, "@@DC_PRUNE bogus\nDeleted X:\nabc\n"])
def test_garbled_prune_output_counts_nothing(garbage: str) -> None:
    assert parse_removed_counts(garbage) == {}
    assert parse_reclaimed_bytes(garbage) == 0


# --- Vulnerability scans -----------------------------------------------------


def _trivy(vid: str, pkg: str, ver: str, fixed: str, sev: str, title: str = "") -> str:
    return f"V\t{vid}\t{pkg}\t{ver}\t{fixed}\t{sev}\thttps://avd.aquasec.com/nvd/{vid.lower()}\t{title}"


def _grype(vid: str, pkg: str, ver: str, fixed: str, sev: str) -> str:
    return f"V\t{vid}\t{pkg}\t{ver}\t{fixed} \t{sev}\thttps://nvd.nist.gov/vuln/detail/{vid}\t"


def test_both_scanners_findings_are_merged_per_image() -> None:
    raw = "\n".join(
        [
            "@@DC_SCANNER trivy 0.56.2",
            "@@DC_SCANNER grype 0.82.0",
            "@@DC_IMAGE nginx:1.27",
            "@@DC_BEGIN trivy",
            _trivy("CVE-2024-0001", "openssl", "3.0.1", "3.0.2", "MEDIUM", "Buffer overflow"),
            _trivy("CVE-2024-0002", "zlib", "1.2.13", "", "LOW"),
            "",
            "@@DC_END trivy 0",
            "@@DC_BEGIN grype",
            _grype("CVE-2024-0001", "openssl", "3.0.1", "3.0.2", "High"),
            _grype("GHSA-xxxx-yyyy-zzzz", "lodash", "4.17.0", "4.17.21", "Negligible"),
            "",
            "@@DC_END grype 0",
            "@@DC_IMAGE postgres:16",
            "@@DC_BEGIN trivy",
            _trivy("CVE-2024-9999", "libpq", "16.0", "16.1", "CRITICAL"),
            "@@DC_END trivy 1",
            "@@DC_ERR trivy FATAL image scan error: unable to find the specified image",
            "@@DC_BEGIN grype",
            "@@DC_END grype 0",
        ]
    )

    nginx, postgres = parse_scan_output(raw)

    assert nginx.image == "nginx:1.27"
    assert nginx.scanners == {"trivy": "0.56.2", "grype": "0.82.0"}
    assert nginx.errors == {}
    openssl = nginx.vulnerabilities[0]
    assert (openssl["id"], openssl["severity"], openssl["scanners"]) == (
        "CVE-2024-0001", "high", ["grype", "trivy"])
    assert openssl["title"] == "Buffer overflow"
    assert nginx.counts == {"critical": 0, "high": 1, "medium": 0, "low": 2, "unknown": 0}

    # A failed scanner contributes no findings, only its error.
    assert postgres.scanners == {"grype": "0.82.0"}
    assert postgres.vulnerabilities == []
    assert postgres.errors["trivy"].startswith("FATAL image scan error")
    assert postgres.ok


def test_a_scanner_that_never_reported_is_an_error() -> None:
    (result,) = parse_scan_output("@@DC_IMAGE alpine:3\n")

    assert not result.ok
    assert result.errors == {"trivy": "No result.", "grype": "No result."}


def test_scan_lines_with_bad_ids_or_urls_are_sanitized() -> None:
    raw = "\n".join(
        [
            "@@DC_IMAGE x",
            "@@DC_BEGIN trivy",
            "V\t$(id)\tpkg\t1\t\tHIGH\thttps://x\t",
            "V\tCVE-1\tpkg\t1\t\tHIGH\tjavascript:alert(1)\t",
            "@@DC_END trivy 0",
        ]
    )
    (result,) = parse_scan_output(raw)

    assert [(v["id"], v["url"]) for v in result.vulnerabilities] == [("CVE-1", "")]


@pytest.mark.parametrize(("value", "expected"), [
    ("CRITICAL", "critical"), (" High ", "high"), ("Negligible", "low"),
    ("minimal", "low"), ("weird", "unknown"), ("", "unknown"),
])
def test_severities_are_normalized(value: str, expected: str) -> None:
    assert normalize_severity(value) == expected


def test_merge_keeps_the_first_non_empty_details() -> None:
    base = {"id": "CVE-1", "pkg": "p", "installed": "1", "url": "", "title": ""}
    merged = merge([
        {**base, "fixed": "", "severity": "low", "scanners": ["grype"]},
        {**base, "fixed": "2", "severity": "medium", "scanners": ["trivy"], "title": "T"},
    ])

    assert merged == [{**base, "fixed": "2", "severity": "medium", "title": "T",
                       "scanners": ["grype", "trivy"]}]


@pytest.mark.parametrize("garbage", _GARBAGE)
def test_garbled_scan_output_does_not_raise(garbage: str) -> None:
    assert parse_scan_output(garbage) == []


# --- Container updates -------------------------------------------------------


def test_pull_output_reports_whether_the_image_changed() -> None:
    raw = (f"@@DC_OLD_ID {_OLD}\n1.27: Pulling from library/nginx\nStatus: Downloaded newer image\n"
           f"@@DC_NEW_ID {_NEW}\n")

    result = parse_pull_output(raw)

    assert (result.old_id, result.new_id) == (_OLD, _NEW)
    assert result.changed and not result.failed
    same = parse_pull_output(f"@@DC_OLD_ID {_OLD}\n@@DC_NEW_ID {_OLD}\n")
    assert not same.changed


def test_pull_output_failures_and_garbage() -> None:
    failed = parse_pull_output("@@DC_OLD_ID \nError: manifest unknown\n@@DC_PULL_FAILED\n")
    assert failed.failed and not failed.changed
    junk = parse_pull_output("@@DC_OLD_ID $(id)\n@@DC_NEW_ID not-an-id\n")
    assert (junk.old_id, junk.new_id, junk.changed) == ("", "", False)


def test_a_plan_is_read_from_container_and_image_inspect() -> None:
    image = {"Id": _OLD, "RepoDigests": ["ghcr.io/immich-app/immich-server@sha256:" + "d" * 64]}
    raw = json.dumps([_inspect_row()]) + "\n@@DC_SPLIT\n" + json.dumps([image])

    container, image_record = parse_plan_output(raw)
    plan = plan_from_inspect(container, image_record)

    assert plan.name == "immich_server"
    assert plan.ref == "ghcr.io/immich-app/immich-server:release"
    assert plan.image_id == _OLD
    assert plan.running and plan.is_compose
    assert plan.compose_files == ["/opt/immich/compose.yml", "/opt/immich/override.yml"]
    assert plan.repo_digests and plan.repo_digests[0].endswith("d" * 64)


def test_a_plain_container_without_image_inspect_is_still_planned() -> None:
    row = _inspect_row(Config={"Image": "nginx:1.27", "Labels": None})
    container, image = parse_plan_output(json.dumps([row]) + "\n@@DC_SPLIT\n")

    plan = plan_from_inspect(container, image)

    assert image == {}
    assert not plan.is_compose and plan.repo_digests == []


@pytest.mark.parametrize(
    "raw", ["", "Error: No such container: x", "[]", "{bad json\n@@DC_SPLIT\n"]
)
def test_a_missing_or_garbled_plan_raises_a_command_error(raw: str) -> None:
    with pytest.raises(DockerCommandError):
        parse_plan_output(raw)


def test_recreate_output_is_classified() -> None:
    done = parse_recreate_output("@@DC_STEP stop\n@@DC_STEP create\n{\"Id\":\"x\"}\n@@DC_DONE\n")
    unstable = parse_recreate_output(
        "@@DC_STEP start\n@@DC_UNSTABLE\n  | panic\n@@DC_RESTORE\n")
    failed = parse_recreate_output("@@DC_FAILED create\n@@DC_RESTORE\n")

    assert (done.done, done.restored, done.failed_step) == (True, False, "")
    assert (unstable.unstable, unstable.restored, unstable.done) == (True, True, False)
    assert (failed.failed_step, failed.restored) == ("create", True)


# --- Compose stacks ----------------------------------------------------------


def test_compose_commit_and_failed_step_markers() -> None:
    raw = f"Cloning...\n@@DC_COMMIT {_SHA}\n@@DC_STEP config\n@@DC_FAILED config\n"

    assert docker_compose.parse_commit(raw) == _SHA
    assert docker_compose.failed_step(raw) == "config"
    assert docker_compose.parse_commit("@@DC_COMMIT \n") is None
    assert docker_compose.parse_commit("@@DC_COMMIT deadbeef") is None
    assert docker_compose.failed_step("all good\n@@DC_DONE") is None


# --- restic ------------------------------------------------------------------


def test_the_restic_backup_summary_is_read_from_its_json_stream() -> None:
    snapshot = "a" * 64
    raw = "\n".join(
        [
            "repository 1234abcd opened (version 2, compression level auto)",
            json.dumps({"message_type": "status", "percent_done": 0.5}),
            json.dumps({
                "message_type": "summary", "files_new": 10, "files_changed": 2,
                "files_unmodified": 100, "data_added": 4096,
                "total_bytes_processed": 1048576, "snapshot_id": snapshot,
            }),
        ]
    )

    summary = restic.parse_backup_summary(raw)

    assert summary == restic.BackupSummary(
        snapshot_id=snapshot, bytes_added=4096, bytes_processed=1048576, files=112
    )


@pytest.mark.parametrize("garbage", [*_GARBAGE, '{"message_type":"summary","snapshot_id":"$(id)"}'])
def test_garbled_restic_summaries_are_empty(garbage: str) -> None:
    summary = restic.parse_backup_summary(garbage)

    assert summary.snapshot_id == "" and summary.bytes_added is None


def test_restic_snapshots_newest_first_and_invalid_ids_dropped() -> None:
    snapshots = [
        {"id": "a" * 64, "short_id": "aaaaaaaa", "time": "2026-10-01T02:00:00Z",
         "hostname": "nas", "paths": ["/backup"], "summary": {"total_bytes_processed": 10}},
        {"id": "b" * 64, "time": "2026-10-02T02:00:00Z", "hostname": "nas", "paths": ["/backup"]},
        {"id": "--delete", "time": "2026-10-03T02:00:00Z"},
        "not a dict",
    ]
    raw = "repository opened\n" + json.dumps(snapshots)

    parsed = restic.parse_snapshots(raw)

    assert [s["id"] for s in parsed] == ["b" * 64, "a" * 64]
    assert parsed[0]["short_id"] == "bbbbbbbb"
    assert (parsed[1]["size_bytes"], parsed[0]["size_bytes"]) == (10, None)


@pytest.mark.parametrize("garbage", [*_GARBAGE, "Fatal: wrong password or no key found"])
def test_garbled_restic_snapshots_are_empty(garbage: str) -> None:
    assert restic.parse_snapshots(garbage) == []


def test_restic_failed_step() -> None:
    assert restic.failed_step("@@DC_STEP init\n@@DC_FAILED init\n") == "init"
    assert restic.failed_step("@@DC_DONE") is None


# --- Files in containers and volumes -----------------------------------------


def test_a_directory_listing_is_parsed_directories_first() -> None:
    raw = "\n".join(
        [
            "regular file|1024|1700000000|-rw-r--r--|root|root|nginx.conf",
            "directory|4096|1700000001|drwxr-xr-x|root|root|conf.d",
            "symbolic link|11|1700000002|lrwxrwxrwx|root|root|current",
            "regular empty file|0|1700000003|-rw-------|www|www|.env",
            "fifo|0|1700000004|prw-r--r--|root|root|a|pipe|name",
            "garbage line",
            "regular file|1|1|-rw-r--r--|root|root|",
            "regular file|x|y|-rw-r--r--|root|root|odd",
        ]
    )

    entries = parse_listing(raw)

    assert entries is not None
    assert [(e["name"], e["kind"]) for e in entries] == [
        ("conf.d", "dir"),
        (".env", "file"),
        ("a|pipe|name", "other"),
        ("current", "link"),
        ("nginx.conf", "file"),
        ("odd", "file"),
    ]
    nginx = next(e for e in entries if e["name"] == "nginx.conf")
    assert (nginx["size"], nginx["mtime"], nginx["owner"]) == (1024, 1700000000, "root:root")
    odd = next(e for e in entries if e["name"] == "odd")
    assert (odd["size"], odd["mtime"]) == (None, None)


def test_a_missing_directory_is_none_and_garbage_is_empty() -> None:
    assert parse_listing("@@DC_NODIR\n") is None
    for garbage in _GARBAGE:
        assert parse_listing(garbage) == []


def test_a_file_round_trips_through_a_tar_stream_with_its_owner() -> None:
    stream = build_tar("app.conf", b"key=value\n", mode=0o100640, uid=1000, gid=33)

    read = first_file(stream)

    assert read is not None
    assert (read.name, read.content, read.mode, read.uid, read.gid) == (
        "app.conf", b"key=value\n", 0o640, 1000, 33)


def test_the_owner_is_read_from_the_first_header_alone() -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("data.db")
        info.size, info.mode, info.uid, info.gid = 3, 0o600, 999, 999
        archive.addfile(info, io.BytesIO(b"abc"))

    assert first_member_owner(buffer.getvalue()[:512]) == (0o600, 999, 999)


def test_a_tar_without_a_regular_file_or_a_broken_one_reads_as_none() -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("dir")
        info.type = tarfile.DIRTYPE
        archive.addfile(info)

    assert first_file(buffer.getvalue()) is None
    assert first_member_owner(buffer.getvalue()) is None
    for broken in (b"", b"\x00" * 10, b"not a tar at all" * 64):
        assert first_file(broken) is None
        assert first_member_owner(broken) is None


@pytest.mark.parametrize("name", ["", "a/b", ".", "..", "a\0b"])
def test_a_tar_is_never_built_with_a_path_as_its_name(name: str) -> None:
    with pytest.raises(DockerCommandError):
        build_tar(name, b"")


def test_removed_images_are_counted_from_before_and_after_not_from_layers() -> None:
    raw = (
        "@@DC_PRUNE images\n"
        "Deleted Images:\n"
        "untagged: nginx:1.25\n"
        "untagged: nginx:old\n"
        "deleted: sha256:aaa\n"
        "deleted: sha256:bbb\n"
        "\n"
        "Total reclaimed space: 10MB\n"
        "@@DC_IMAGES_REMOVED 1\n"
    )

    assert parse_removed_counts(raw)["images"] == 1


def test_backup_summary_with_no_files_counts_zero() -> None:
    raw = (
        '{"message_type":"summary","files_new":0,"files_changed":0,'
        '"files_unmodified":0,"snapshot_id":"0123abcd"}'
    )

    assert restic.parse_backup_summary(raw).files == 0


def test_redacting_a_rest_repository_with_an_odd_port_does_not_crash() -> None:
    assert restic.redact_repository("rest:https://u:p@host:abc/repo") == "rest:https://***@host:abc/repo"
    assert restic.redact_repository("rest:https://u:p@host:8000/repo") == "rest:https://***@host:8000/repo"
