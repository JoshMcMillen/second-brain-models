"""Strict JSON input and this repository's canonical JSON encoding.

Canonical documents are UTF-8, have lexicographically sorted object keys, use
no insignificant whitespace, preserve Unicode, reject non-finite numbers, and
carry no trailing newline in the signed bytes.  All producers and verifiers in
this repository use this one implementation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .errors import DocumentError


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DocumentError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise DocumentError(f"non-finite JSON number {value!r}")


def loads_strict(raw: str | bytes) -> Any:
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="strict")
        return json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        if isinstance(exc, DocumentError):
            raise
        raise DocumentError(f"invalid JSON: {exc}") from exc


def load_json(path: Path | str) -> Any:
    source = Path(path)
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise DocumentError(f"could not read {source}: {exc}") from exc
    return loads_strict(raw)


def canonical_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise DocumentError(f"value is not canonical JSON data: {exc}") from exc
    return text.encode("utf-8")


def canonical_file_bytes(path: Path | str) -> bytes:
    return canonical_bytes(load_json(path))


def atomic_write(path: Path | str, data: bytes, *, private: bool = False) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=target.parent)
    temp = Path(temp_name)
    try:
        if private and os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
        if private and os.name != "nt":
            target.chmod(0o600)
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        finally:
            raise


def write_canonical(path: Path | str, value: Any) -> None:
    atomic_write(path, canonical_bytes(value) + b"\n")
