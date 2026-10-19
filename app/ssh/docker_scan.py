"""Vulnerability scans of Docker images with Trivy and Grype, both run in
their own containers on the machine (`docker_cli.TRIVY_IMAGE`,
`docker_cli.GRYPE_IMAGE`) against the images in its Docker.

**Always the newest scanner.** Each scan pulls both scanner images first
(a failed pull — no internet — falls back to the copy already there), and
each scanner refreshes its vulnerability database, kept between runs in a
named volume (`docker_cli.TRIVY_CACHE_VOLUME`, `GRYPE_CACHE_VOLUME`).

**Both scanners, one list.** A finding is the same finding when both
report the same vulnerability id for the same package and version; it
keeps the higher of the two severities and says which scanners saw it.
Either scanner failing still leaves the other's findings, and the failure
is kept with the scan.

**Little leaves the machine.** Instead of the scanners' full JSON reports
(megabytes per image, mostly descriptions), each prints one tab-separated
line per finding through a Go template: Trivy's inline, Grype's from a
temporary file, since Grype only reads templates from files.

The scanners see the images through the Docker socket, read-only; they
get no other access to the machine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.ssh.docker_cli import (
    DOCKER_SOCKET,
    GRYPE_CACHE_VOLUME,
    GRYPE_IMAGE,
    HELPER_LABEL,
    TRIVY_CACHE_VOLUME,
    TRIVY_IMAGE,
    DockerCommandError,
    is_image_valid,
    q,
)

SCANNERS = ("trivy", "grype")
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
# Findings kept per scan, most severe first.
MAX_FINDINGS = 2000
# Images one scan job takes on.
MAX_IMAGES = 200

# One line per finding: V, id, package, installed, fixed, severity, url, title.
_TRIVY_TEMPLATE = (
    "{{- range .Results }}{{- range .Vulnerabilities }}"
    "V\t{{ .VulnerabilityID }}\t{{ .PkgName }}\t{{ .InstalledVersion }}\t"
    "{{ .FixedVersion }}\t{{ .Severity }}\t{{ .PrimaryURL }}\t{{ .Title }}\n"
    "{{ end }}{{ end }}"
)
_GRYPE_TEMPLATE = (
    "{{- range .Matches }}"
    "V\t{{ .Vulnerability.ID }}\t{{ .Artifact.Name }}\t{{ .Artifact.Version }}\t"
    "{{ range .Vulnerability.Fix.Versions }}{{ . }} {{ end }}\t"
    "{{ .Vulnerability.Severity }}\t{{ .Vulnerability.DataSource }}\t\n"
    "{{ end }}"
)

_RUN = f"$D run --rm --pull missing --label {HELPER_LABEL} --user 0:0 "


def build_scan_script(images: list[str]) -> str:
    """The detached job's script: pull both scanners, print their versions,
    then scan each image with each scanner."""
    if not images:
        raise DockerCommandError("No images to scan.")
    if len(images) > MAX_IMAGES:
        raise DockerCommandError(f"At most {MAX_IMAGES} images at once.")
    for image in images:
        if not is_image_valid(image):
            raise DockerCommandError(f'"{image}" is not a valid image.')
    socket = f"-v {DOCKER_SOCKET}:{DOCKER_SOCKET}:ro"
    trivy = (
        f"{_RUN}{socket} -v {TRIVY_CACHE_VOLUME}:/cache {TRIVY_IMAGE} image "
        "--cache-dir /cache --quiet --scanners vuln --timeout 20m "
        f"--format template --template {q(_TRIVY_TEMPLATE)}"
    )
    grype = (
        f'{_RUN}{socket} -v {GRYPE_CACHE_VOLUME}:/cache -v "$tpl":/debcontrol.tmpl:ro '
        f"-e GRYPE_DB_CACHE_DIR=/cache -e GRYPE_CHECK_FOR_APP_UPDATE=false {GRYPE_IMAGE} "
        "-q -o template -t /debcontrol.tmpl"
    )
    lines = [
        'tpl="$(mktemp)"; err="$(mktemp)"; trap \'rm -f "$tpl" "$err"\' EXIT',
        f"printf '%s' {q(_GRYPE_TEMPLATE)} > \"$tpl\"",
        f"$D pull -q {TRIVY_IMAGE} >/dev/null 2>&1 || true",
        f"$D pull -q {GRYPE_IMAGE} >/dev/null 2>&1 || true",
        f'echo "@@DC_SCANNER trivy $({_RUN}{TRIVY_IMAGE} --version 2>/dev/null '
        "| awk '/^Version:/{print $2; exit}')\"",
        f'echo "@@DC_SCANNER grype $({_RUN}{GRYPE_IMAGE} version 2>/dev/null '
        "| awk '/^Version:/{print $2; exit}')\"",
    ]
    for image in images:
        quoted = q(image)
        lines += [
            f"echo {q('@@DC_IMAGE ' + image)}",
            "echo '@@DC_BEGIN trivy'",
            f'{trivy} {quoted} 2>"$err"; rc=$?',
            'echo; echo "@@DC_END trivy $rc"',
            '[ "$rc" = 0 ] || echo "@@DC_ERR trivy $(tail -c 400 "$err" | tr \'\\n\' \' \')"',
            "echo '@@DC_BEGIN grype'",
            f'{grype} {q("docker:" + image)} 2>"$err"; rc=$?',
            'echo; echo "@@DC_END grype $rc"',
            '[ "$rc" = 0 ] || echo "@@DC_ERR grype $(tail -c 400 "$err" | tr \'\\n\' \' \')"',
        ]
    # Fails only when nothing at all could be scanned (see parse_scan_output).
    return "\n".join(lines) + "\n"


@dataclass
class ImageScanResult:
    image: str
    scanners: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.scanners)


def normalize_severity(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in ("negligible", "minimal"):
        return "low"
    return lowered if lowered in _RANK else "unknown"


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _finding(line: str, scanner: str) -> dict[str, Any] | None:
    parts = line.split("\t", 7)
    if len(parts) < 7 or parts[0] != "V":
        return None
    vuln_id = parts[1].strip()
    if not _ID_RE.match(vuln_id):
        return None
    fixed = " ".join(parts[4].split())
    url = parts[6].strip()
    return {
        "id": vuln_id,
        "pkg": parts[2].strip()[:255],
        "installed": parts[3].strip()[:128],
        "fixed": fixed[:255],
        "severity": normalize_severity(parts[5]),
        "url": url[:512] if url.startswith(("https://", "http://")) else "",
        "title": (parts[7].strip() if len(parts) > 7 else "")[:300],
        "scanners": [scanner],
    }


def merge(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per (id, package, installed version): the higher severity,
    every scanner that reported it, the first non-empty fix/url/title."""
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for finding in findings:
        key = (finding["id"], finding["pkg"], finding["installed"])
        existing = merged.get(key)
        if existing is None:
            merged[key] = {**finding, "scanners": list(finding["scanners"])}
            continue
        if _RANK[finding["severity"]] < _RANK[existing["severity"]]:
            existing["severity"] = finding["severity"]
        for scanner in finding["scanners"]:
            if scanner not in existing["scanners"]:
                existing["scanners"].append(scanner)
        for key_name in ("fixed", "url", "title"):
            if not existing[key_name] and finding[key_name]:
                existing[key_name] = finding[key_name]
    ordered = sorted(merged.values(), key=lambda f: (_RANK[f["severity"]], f["id"], f["pkg"]))
    for finding in ordered:
        finding["scanners"].sort()
    return ordered


def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


class _ScanParser:
    """State while reading `build_scan_script`'s output line by line."""

    def __init__(self) -> None:
        self.versions: dict[str, str] = {}
        self.results: list[ImageScanResult] = []
        self.current: ImageScanResult | None = None
        self.scanner: str | None = None
        self.found: dict[str, list[dict[str, Any]]] = {}

    def finish(self) -> None:
        if self.current is None:
            return
        merged = merge([f for findings in self.found.values() for f in findings])
        self.current.counts = count_by_severity(merged)
        self.current.vulnerabilities = merged[:MAX_FINDINGS]
        self.results.append(self.current)
        self.current = None

    def marker(self, line: str, current: ImageScanResult) -> None:
        parts = line.split(" ", 2)
        name = parts[1].strip() if len(parts) > 1 else ""
        if name not in SCANNERS:
            return
        if parts[0] == "@@DC_BEGIN":
            self.scanner = name
            self.found[name] = []
        elif parts[0] == "@@DC_END":
            if len(parts) > 2 and parts[2].strip() == "0":
                current.scanners[name] = self.versions.get(name, "")
            else:
                self.found.pop(name, None)
            self.scanner = None
        elif parts[0] == "@@DC_ERR":
            current.errors[name] = (parts[2] if len(parts) > 2 else "").strip()[:400]

    def line(self, line: str) -> None:
        if line.startswith("@@DC_SCANNER "):
            parts = line.split()
            if len(parts) >= 2 and parts[1] in SCANNERS:
                self.versions[parts[1]] = parts[2][:32] if len(parts) > 2 else ""
        elif line.startswith("@@DC_IMAGE "):
            self.finish()
            self.current = ImageScanResult(image=line[len("@@DC_IMAGE ") :].strip()[:512])
            self.found = {}
            self.scanner = None
        elif self.current is None:
            return
        elif line.startswith(("@@DC_BEGIN ", "@@DC_END ", "@@DC_ERR ")):
            self.marker(line, self.current)
        elif self.scanner is not None and line.startswith("V\t"):
            finding = _finding(line, self.scanner)
            if finding is not None:
                self.found[self.scanner].append(finding)


def parse_scan_output(raw: str) -> list[ImageScanResult]:
    """The per-image results of `build_scan_script`'s output. Never raises."""
    parser = _ScanParser()
    for line in raw.splitlines():
        parser.line(line)
    parser.finish()
    for result in parser.results:
        for name in SCANNERS:
            if name not in result.scanners and name not in result.errors:
                result.errors[name] = "No result."
    return parser.results
