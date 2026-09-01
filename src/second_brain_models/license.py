"""Exact byte binding for licenses redistributed with models and runtimes."""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import DocumentError


def validate_license_binding(
    manifest_path: Path | str, license_data: dict[str, Any], repo_root: Path | str,
) -> Path:
    """Require one adjacent, regular LICENSE whose bytes match both signed paths."""
    root = Path(repo_root).resolve()
    source = Path(manifest_path).resolve()
    try:
        source.relative_to(root)
    except ValueError as exc:
        raise DocumentError("manifest must be inside the repository for license validation") from exc
    expected_source = source.parent / "LICENSE"
    expected_relative = expected_source.relative_to(root).as_posix()
    if license_data["repository_path"] != expected_relative:
        raise DocumentError("license repository_path must name the LICENSE adjacent to its manifest")

    relative = PurePosixPath(license_data["repository_path"])
    target = root.joinpath(*relative.parts)
    if target.is_symlink() or any(parent.is_symlink() for parent in target.parents if parent != root.parent):
        raise DocumentError("license path may not contain symlinks")
    try:
        resolved = target.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise DocumentError("license path is missing or escapes the repository") from exc
    if resolved != expected_source.resolve() or not resolved.is_file():
        raise DocumentError("license must be the regular LICENSE adjacent to its manifest")

    raw = resolved.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if license_data["sha256"] != digest:
        raise DocumentError("license SHA-256 does not match the committed LICENSE bytes")
    if license_data["size_bytes"] != len(raw):
        raise DocumentError("license size does not match the committed LICENSE bytes")
    if license_data["path"] != f"licenses/{digest}/LICENSE":
        raise DocumentError("public license path must embed the exact license SHA-256")
    return resolved
