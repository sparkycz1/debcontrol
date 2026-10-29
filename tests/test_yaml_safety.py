"""app.core.yaml_safety: deep nesting and (optionally) aliases are refused
before PyYAML builds anything, in the rule YAML import and compose check."""

from __future__ import annotations

import time

import pytest
import yaml

from app.core import yaml_safety
from app.services.docker_stacks import validate_compose
from app.ssh.docker_cli import DockerCommandError

DEEP = [
    "[" * 5000,
    "{a: " * 5000,
    "".join(" " * i + "-\n" for i in range(500)) + " " * 500 + "x\n",
]


@pytest.mark.parametrize("text", DEEP)
def test_deep_nesting_is_refused_quickly(text: str) -> None:
    start = time.perf_counter()
    with pytest.raises(yaml.YAMLError, match="nested more than"):
        yaml_safety.load(text)
    assert time.perf_counter() - start < 2


def test_normal_documents_and_aliases() -> None:
    text = "x: &a [1, 2]\ny: *a\n"
    assert yaml_safety.load(text) == {"x": [1, 2], "y": [1, 2]}
    with pytest.raises(yaml.YAMLError, match="aliases"):
        yaml_safety.load(text, allow_aliases=False)
    assert yaml_safety.load("[" * 64 + "]" * 64) is not None


def test_compose_check_refuses_deep_nesting() -> None:
    with pytest.raises(DockerCommandError, match="not valid YAML"):
        validate_compose("services:\n  a: " + "[" * 200 + "\n")
