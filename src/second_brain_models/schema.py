"""Repository-owned JSON Schema validation."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource

from .errors import DocumentError
from .jsonio import load_json
from .yamlio import load_data


SCHEMA_FILES = {
    "manifest": "manifest-v1.schema.json",
    "catalog": "catalog-v1.schema.json",
    "result": "result-v1.schema.json",
    "revocation": "revocation-v1.schema.json",
    "runtime": "runtime-v1.schema.json",
}


def validate_schema_set(repo_root: Path | str) -> None:
    root = Path(repo_root)
    identifiers: set[str] = set()
    for kind, filename in SCHEMA_FILES.items():
        document = load_json(root / "schemas" / filename)
        try:
            Draft202012Validator.check_schema(document)
        except SchemaError as exc:
            raise DocumentError(f"repository {kind} schema is invalid: {exc.message}") from exc
        identifier = document.get("$id") if isinstance(document, dict) else None
        if not isinstance(identifier, str) or identifier in identifiers:
            raise DocumentError(f"repository {kind} schema has missing or duplicate $id")
        identifiers.add(identifier)


def schema_path(repo_root: Path | str, kind: str) -> Path:
    try:
        name = SCHEMA_FILES[kind]
    except KeyError as exc:
        raise DocumentError(f"unknown document kind {kind!r}") from exc
    return Path(repo_root) / "schemas" / name


def validate_value(value: Any, kind: str, repo_root: Path | str) -> None:
    schema = load_json(schema_path(repo_root, kind))
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise DocumentError(f"repository {kind} schema is invalid: {exc.message}") from exc
    resources: list[tuple[str, Resource[Any]]] = []
    schema_dir = Path(repo_root) / "schemas"
    for filename in SCHEMA_FILES.values():
        candidate = schema_dir / filename
        if not candidate.is_file():
            continue
        document = load_json(candidate)
        Draft202012Validator.check_schema(document)
        identifier = document.get("$id")
        if isinstance(identifier, str):
            resources.append((identifier, Resource.from_contents(document)))
    registry = Registry().with_resources(resources)
    errors = sorted(
        Draft202012Validator(schema, registry=registry, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        lines = []
        for error in errors[:20]:
            location = "/".join(str(part) for part in error.absolute_path) or "$"
            lines.append(f"{location}: {error.message}")
        suffix = f"; and {len(errors) - 20} more" if len(errors) > 20 else ""
        raise DocumentError(f"{kind} schema validation failed: " + "; ".join(lines) + suffix)


def validate_file(path: Path | str, kind: str, repo_root: Path | str) -> Any:
    value = load_data(path)
    validate_value(value, kind, repo_root)
    return value
