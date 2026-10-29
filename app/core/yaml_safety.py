"""Parsing YAML that a user typed or uploaded.

PyYAML builds nested collections recursively, so a document nested a few
hundred levels deep ends in a RecursionError, and deeply nested flow
collections (`[[[[...`) take seconds to parse on the pure-Python build.
`load` first walks the parser's event stream (flat, no objects built) and
refuses anything nested deeper than any real file is, then parses."""

from __future__ import annotations

from typing import Any

import yaml

MAX_DEPTH = 64


def load(text: str, *, allow_aliases: bool = True, max_depth: int = MAX_DEPTH) -> Any:
    """`yaml.safe_load` with a nesting limit; raises `yaml.YAMLError`.

    `allow_aliases=False` also refuses anchors/aliases, ruling out a
    "billion laughs" document whose shared references blow up once a
    caller walks them."""
    depth = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.CollectionStartEvent):
            depth += 1
            if depth > max_depth:
                raise yaml.YAMLError(f"The YAML is nested more than {max_depth} levels deep.")
        elif isinstance(event, yaml.CollectionEndEvent):
            depth -= 1
        elif not allow_aliases and isinstance(event, yaml.AliasEvent):
            raise yaml.YAMLError("YAML aliases (*name) aren't supported here.")
    return yaml.safe_load(text)
