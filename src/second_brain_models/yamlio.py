"""Strict YAML loading for declarative manifests.

YAML aliases, custom tags, duplicate keys, and non-string mapping keys are not
accepted.  The resulting value is ordinary JSON-compatible data.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .errors import DocumentError


class StrictSafeLoader(yaml.SafeLoader):
    pass


def _no_aliases(self: StrictSafeLoader, event: yaml.events.Event) -> None:
    if isinstance(event, yaml.events.AliasEvent):
        raise DocumentError("YAML aliases are forbidden")
    return yaml.SafeLoader.compose_node(self, event.parent, event.index)  # type: ignore[attr-defined]


def _mapping(loader: StrictSafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise DocumentError("YAML mapping keys must be strings")
        if key in result:
            raise DocumentError(f"duplicate YAML key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _reject_non_json(value: Any, where: str = "$") -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise DocumentError(f"non-finite YAML number at {where}")
        return value
    if isinstance(value, list):
        return [_reject_non_json(item, f"{where}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        return {key: _reject_non_json(item, f"{where}.{key}") for key, item in value.items()}
    raise DocumentError(f"YAML value at {where} is not JSON-compatible")


def load_yaml(path: Path | str) -> Any:
    source = Path(path)
    try:
        raw = source.read_text(encoding="utf-8")
        if "&" in raw or "*" in raw:
            # Avoid accepting alias-driven expansion.  This conservative check
            # may reject those characters inside strings, which is acceptable
            # for the repository's machine-authored manifests.
            for token in yaml.scan(raw):
                if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken, yaml.tokens.TagToken)):
                    raise DocumentError("YAML aliases, anchors, and custom tags are forbidden")
        return _reject_non_json(yaml.load(raw, Loader=StrictSafeLoader))
    except DocumentError:
        raise
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise DocumentError(f"could not load YAML {source}: {exc}") from exc


def load_data(path: Path | str) -> Any:
    source = Path(path)
    if source.suffix.casefold() in {".yaml", ".yml"}:
        return load_yaml(source)
    from .jsonio import load_json

    return load_json(source)
