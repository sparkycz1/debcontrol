"""Every fuzz target (`fuzz/targets.py`) run over a fixed seed corpus plus a
few hundred deterministic pseudo-random inputs — so a contract a target
checks can't regress unnoticed between the coverage-guided runs in
`.github/workflows/fuzz.yml`, and so the targets run on every OS (Atheris
itself is Linux-only). An input the fuzzer once crashed on belongs in
`_SEEDS` once it's fixed."""

from __future__ import annotations

import random
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from fuzz.targets import TARGETS

_TOKENS = [
    "\n", "\t", " ", ":", "=", ",", ";", "|", "/", "\\", "[", "]", "{", "}", '"', "'",
    "-", ".", "0", "1", "99999", "-1", "nan", "inf", "%", "@", "http://", "https://",
    "//", "?", "#", "::", "\x00", "\x7f", "é", chr(0x2028), "null", "[]", "{}", "- ",
    "&a", "*a", "!!python/object", "---", "kB", "MiB", "running", "OK", "CVE-2024-1",
    "urgency=high", ") unstable;", '{"MESSAGE":', '"__CURSOR"', "vmid", "size",
]

# Inputs that once broke a target, kept so they can't come back.
_SEEDS: list[bytes] = [
    b"",
    b"\x00" * 12,
    # A DNS reply whose question count runs past the end of the packet.
    b"\x00\x00\x81\x80\x00\x05\x00\x00\x00\x00\x00\x00\x07example",
    # A webhook URL with a broken IPv6 host / an out-of-range port.
    b"https://[::1/hook",
    b"https://example.com:99999/hook",
    # A tag cut at its length cap right after a space.
    b"a" * 63 + b" b",
    b"/\\evil.example",
    b"/\t/evil.example",
    b"*a [&a x]",
    # The documented "can't reach Docker" answer (not a crash).
    b"\n@@NOACCESS\n",
    b"/var/log/../../etc/shadow",
    # JSON from a machine (journal, pvesh, sensors) nested far too deep.
    b"[" * 5000,
    b'{"MESSAGE": "x"}\n' + b"[" * 5000 + b"\n",
]


def _inputs(name: str, count: int = 300) -> list[bytes]:
    rng = random.Random(name)  # noqa: S311 - reproducible test inputs, not secrets
    inputs = list(_SEEDS)
    for _ in range(count):
        if rng.random() < 0.2:
            inputs.append(rng.randbytes(rng.randint(0, 120)))
        else:
            text = "".join(rng.choice(_TOKENS) for _ in range(rng.randint(0, 40)))
            inputs.append(text.encode("utf-8", "surrogatepass"))
    return inputs


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_fuzz_target_holds_its_contract(name: str) -> None:
    target: Callable[[bytes], None] = TARGETS[name]
    for data in _inputs(name):
        target(data)


def test_the_fuzz_workflow_runs_every_target() -> None:
    workflow = yaml.safe_load(
        (Path(__file__).parent.parent / ".github" / "workflows" / "fuzz.yml").read_text(
            encoding="utf-8"
        )
    )
    assert sorted(workflow["jobs"]["fuzz"]["strategy"]["matrix"]["target"]) == sorted(TARGETS)
