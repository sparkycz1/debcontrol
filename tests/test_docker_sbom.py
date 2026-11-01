"""Image packages (SBOM) from Trivy's package list: parsing, storing with
the scan, the fleet-wide search (scoped like every other fleet view) and
the CycloneDX download, on the web and through the API."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from app.db.models.docker import DockerImagePackage, DockerImageScan
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.services import docker_sbom, docker_scans
from app.ssh.docker_scan import build_scan_script, parse_scan_output
from app.tasks.docker_jobs import _visible_output
from tests.test_docker_web_support import IMAGE_ID, add_scan, make_docker_machine
from tests.test_update_history import _api_token

OTHER_ID = "sha256:" + "d" * 64


def _output(*, trivy_rc: int = 0) -> str:
    return "\n".join(
        [
            "@@DC_SCANNER trivy 0.68.1",
            "@@DC_SCANNER grype 0.104.0",
            "@@DC_IMAGE nginx:1.27",
            "@@DC_BEGIN trivy",
            "V\tCVE-2026-0001\topenssl\t3.0.1\t3.0.2\tCRITICAL\thttps://x.test/1\tBad",
            "P\topenssl\t3.0.1\tdebian\tpkg:deb/debian/openssl@3.0.1?distro=debian-12",
            "P\topenssl\t3.0.1\tdebian\tpkg:deb/debian/openssl@3.0.1?distro=debian-12",
            "P\tlibssl3\t3.0.1\tdebian\t<nil>",
            "P\trequests\t2.32.0\tpython-pkg\tpkg:pypi/requests@2.32.0",
            "P\t\t1.0\tdebian\t",
            "P\tweird\t1.0\tNot A Type!\tjavascript:alert(1)",
            f"@@DC_END trivy {trivy_rc}",
            "@@DC_BEGIN grype",
            "P\tfromgrype\t1.0\tdebian\t",
            "@@DC_END grype 0",
        ]
    )


def test_the_scan_script_asks_trivy_for_every_package() -> None:
    script = build_scan_script(["nginx:1.27"])
    assert "--list-all-pkgs" in script
    assert "range .Packages" in script


def test_packages_are_parsed_deduplicated_and_cleaned() -> None:
    [result] = parse_scan_output(_output())

    assert result.packages == [
        {
            "name": "openssl",
            "version": "3.0.1",
            "type": "debian",
            "purl": "pkg:deb/debian/openssl@3.0.1?distro=debian-12",
        },
        {"name": "libssl3", "version": "3.0.1", "type": "debian", "purl": ""},
        {
            "name": "requests",
            "version": "2.32.0",
            "type": "python-pkg",
            "purl": "pkg:pypi/requests@2.32.0",
        },
        # An odd type or a non-purl is dropped, never the package.
        {"name": "weird", "version": "1.0", "type": "", "purl": ""},
    ]
    # The vulnerability lines are read as before.
    assert [v["id"] for v in result.vulnerabilities] == ["CVE-2026-0001"]


def test_no_package_list_when_trivy_failed() -> None:
    [result] = parse_scan_output(_output(trivy_rc=1))
    assert result.packages == []


def test_package_lines_stay_out_of_the_job_log() -> None:
    assert _visible_output(_output()).count("\nP\t") == 0
    assert "@@DC_END trivy 0" in _visible_output(_output())


def _machine(name: str, ip: str, group_id: uuid.UUID | None = None) -> Machine:
    return Machine(
        name=name,
        ip_address=ip,
        port=22,
        username="root",
        auth_method=AuthMethod.SSH_KEY,
        group_id=group_id,
        host_key_fingerprint="SHA256:x",
    )


async def test_store_replaces_the_packages_and_keeps_them_when_trivy_failed(
    db_session_factory: Any,
) -> None:
    async with db_session_factory() as db:
        machine = _machine("docker1", "10.0.0.7")
        db.add(machine)
        await db.commit()
        await docker_scans.store(
            db, machine.id, parse_scan_output(_output()), {"nginx:1.27": IMAGE_ID}
        )
        await db.commit()
        first = (await db.execute(select(DockerImagePackage))).scalars().all()

        # Grype alone answered this time: the package list stays as it was.
        failed = parse_scan_output(_output(trivy_rc=1))
        await docker_scans.store(db, machine.id, failed, {"nginx:1.27": IMAGE_ID})
        await db.commit()
        kept = (await db.execute(select(DockerImagePackage))).scalars().all()

        again = parse_scan_output(_output())
        again[0].packages = again[0].packages[:1]
        await docker_scans.store(db, machine.id, again, {"nginx:1.27": IMAGE_ID})
        await db.commit()
        replaced = (await db.execute(select(DockerImagePackage))).scalars().all()

    assert sorted(p.name for p in first) == ["libssl3", "openssl", "requests", "weird"]
    assert {p.name_key for p in first} == {"libssl3", "openssl", "requests", "weird"}
    assert len(kept) == 4
    assert [p.name for p in replaced] == ["openssl"]


async def _seed_packages(db_session_factory: Any) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    async with db_session_factory() as db:
        group_a = MachineGroup(name="group-a")
        group_b = MachineGroup(name="group-b")
        db.add_all([group_a, group_b])
        await db.flush()
        machine_a = _machine("machine-a", "10.90.0.1", group_a.id)
        machine_b = _machine("machine-b", "10.90.0.2", group_b.id)
        db.add_all([machine_a, machine_b])
        await db.flush()
        for machine, version in ((machine_a, "3.0.1"), (machine_b, "3.0.9")):
            scan = DockerImageScan(
                machine_id=machine.id,
                image_id=IMAGE_ID,
                image_ref="nginx:1.27",
                scanners={"trivy": "0.68.1"},
                counts={},
            )
            db.add(scan)
            await db.flush()
            await docker_sbom.replace_packages(
                db,
                scan,
                [
                    {"name": "OpenSSL", "version": version, "type": "debian", "purl": ""},
                    {"name": "libssl3", "version": version, "type": "debian", "purl": ""},
                    {"name": "my_pkg", "version": "1", "type": "python-pkg", "purl": ""},
                    {"name": "myxpkg", "version": "1", "type": "python-pkg", "purl": ""},
                ],
            )
        await db.commit()
        return group_a.id, machine_a.id, machine_b.id


async def test_search_matches_the_name_prefix_in_any_case(db_session_factory: Any) -> None:
    await _seed_packages(db_session_factory)
    async with db_session_factory() as db:
        everyone = select(Machine.id)
        hits, truncated = await docker_sbom.search(db, everyone, "openS")
        none, _ = await docker_sbom.search(db, everyone, "ssl")
        short, _ = await docker_sbom.search(db, everyone, "o")
        # `_` is a literal underscore here, not "any character".
        underscore, _ = await docker_sbom.search(db, everyone, "my_")

    assert [(h.machine.name, h.version) for h in hits] == [
        ("machine-a", "3.0.1"),
        ("machine-b", "3.0.9"),
    ]
    assert truncated is False
    assert none == []
    assert short == []
    assert {h.name for h in underscore} == {"my_pkg"}


async def test_the_search_page_lists_images_and_respects_machine_groups(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    group_a, machine_a, _machine_b = await _seed_packages(db_session_factory)
    await login_as(client, permissions=set(Permission), group_ids={group_a})

    page = await client.get("/security/packages?q=openssl")
    only_images = await client.get("/security/packages?q=openssl&pkg_source=docker")

    assert page.status_code == 200
    assert "machine-a" in page.text
    assert "machine-b" not in page.text
    assert f"/machines/{machine_a}/docker/images/{IMAGE_ID}" in page.text
    assert only_images.status_code == 200
    assert "3.0.1" in only_images.text


async def test_package_search_api_returns_image_packages(
    client: Any, db_session_factory: Any
) -> None:
    await _seed_packages(db_session_factory)
    headers = await _api_token(client)

    both = await client.get("/api/v1/machines/package-search?q=libssl", headers=headers)
    docker_only = await client.get(
        "/api/v1/machines/package-search?q=libssl&pkg_source=docker", headers=headers
    )
    apt_only = await client.get(
        "/api/v1/machines/package-search?q=libssl&pkg_source=apt", headers=headers
    )

    assert both.status_code == 200
    assert {(i["machine"], i["version"]) for i in both.json()["images"]} == {
        ("machine-a", "3.0.1"),
        ("machine-b", "3.0.9"),
    }
    assert both.json()["images"][0]["image"] == "nginx:1.27"
    assert docker_only.json()["results"] == []
    assert len(docker_only.json()["images"]) == 2
    assert apt_only.json()["images"] == []


async def _scan_with_packages(db_session_factory: Any, machine_id: uuid.UUID) -> None:
    await add_scan(db_session_factory, machine_id)
    async with db_session_factory() as db:
        scan = await docker_scans.get_scan(db, machine_id, IMAGE_ID)
        assert scan is not None
        await docker_sbom.replace_packages(
            db,
            scan,
            [
                {"name": "openssl", "version": "3.0.1", "type": "debian", "purl": "pkg:deb/x"},
                {"name": "requests", "version": "2.32", "type": "python-pkg", "purl": ""},
            ],
        )
        await db.commit()


async def test_image_page_shows_the_packages_and_the_download(
    client: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    await _scan_with_packages(db_session_factory, machine_id)

    page = await client.get(f"/machines/{machine_id}/docker/images/{IMAGE_ID}")
    sbom = await client.get(f"/machines/{machine_id}/docker/images/{IMAGE_ID}/sbom")

    assert page.status_code == 200
    assert f"/docker/images/{IMAGE_ID}/sbom" in page.text
    assert "python-pkg 1" in page.text
    assert sbom.status_code == 200
    assert sbom.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert 'filename="nginx_1.27-sbom.cdx.json"' in sbom.headers["content-disposition"]
    document = sbom.json()
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["metadata"]["component"]["name"] == "nginx:1.27"
    assert [c["name"] for c in document["components"]] == ["openssl", "requests"]
    assert document["components"][0]["purl"] == "pkg:deb/x"
    assert "purl" not in document["components"][1]


async def test_sbom_needs_a_scan_and_a_valid_image_id(
    client: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)

    missing = await client.get(f"/machines/{machine_id}/docker/images/{OTHER_ID}/sbom")
    invalid = await client.get(f"/machines/{machine_id}/docker/images/nope/sbom")

    assert missing.status_code == 404
    assert invalid.status_code == 404


async def test_sbom_through_the_api(client: Any, db_session_factory: Any) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    await _scan_with_packages(db_session_factory, machine_id)
    headers = await _api_token(client)

    response = await client.get(
        f"/api/v1/machines/{machine_id}/docker/images/{IMAGE_ID}/sbom", headers=headers
    )
    missing = await client.get(
        f"/api/v1/machines/{machine_id}/docker/images/{OTHER_ID}/sbom", headers=headers
    )

    assert response.status_code == 200
    assert len(response.json()["components"]) == 2
    assert missing.status_code == 404


def test_download_names_are_safe() -> None:
    scan = DockerImageScan(image_id=IMAGE_ID, image_ref='ghcr.io/x/a"b;c:1.0')
    assert docker_sbom.filename(scan) == "a_b_c_1.0-sbom.cdx.json"
