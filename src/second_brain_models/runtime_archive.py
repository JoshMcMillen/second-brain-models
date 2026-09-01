"""Non-executing validation and guarded extraction of pinned runtime archives."""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
from typing import Any, Iterable
import zipfile

from .candidate import sha256_file
from .errors import DocumentError
from .runtime import validate_runtime_manifest


_MAX_ENTRIES = 20_000
_MAX_EXPANDED_BYTES = 20_000_000_000
_MAX_EXPANSION_RATIO = 50


def _safe_member(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name:
        raise DocumentError("runtime archive member uses an unsafe path encoding")
    path = PurePosixPath(name.rstrip("/"))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        raise DocumentError(f"runtime archive member path is unsafe: {name!r}")
    return path


def _zip_members(path: Path) -> list[tuple[PurePosixPath, int, bool, int]]:
    try:
        with zipfile.ZipFile(path) as archive:
            result = []
            for item in archive.infolist():
                mode = item.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if stat.S_ISLNK(mode) or file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise DocumentError(f"runtime ZIP contains symlink or special entry: {item.filename}")
                result.append((_safe_member(item.filename), item.file_size, item.is_dir(), mode))
            return result
    except (OSError, zipfile.BadZipFile) as exc:
        raise DocumentError(f"invalid runtime ZIP: {exc}") from exc


def _tar_members(path: Path) -> list[tuple[PurePosixPath, int, bool, int]]:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            result = []
            for item in archive.getmembers():
                if not (item.isfile() or item.isdir()) or item.issym() or item.islnk() or item.isdev():
                    raise DocumentError(f"runtime tar contains link or special entry: {item.name}")
                result.append((_safe_member(item.name), item.size, item.isdir(), item.mode))
            return result
    except (OSError, tarfile.TarError) as exc:
        raise DocumentError(f"invalid runtime tar.gz: {exc}") from exc


def _members(path: Path, format_name: str) -> list[tuple[PurePosixPath, int, bool, int]]:
    if format_name == "zip":
        return _zip_members(path)
    if format_name == "tar.gz":
        return _tar_members(path)
    raise DocumentError(f"runtime package format {format_name!r} is not supported by the guarded v1 extractor")


def check_runtime_package(
    *, runtime_manifest_path: Path | str, package_root: Path | str,
    platform: str, repo_root: Path | str,
) -> dict[str, Any]:
    runtime = validate_runtime_manifest(runtime_manifest_path, repo_root, require_approved=False)
    matches = [item for item in runtime["packages"] if item["platform"] == platform]
    if len(matches) != 1:
        raise DocumentError("runtime manifest must have exactly one package for the requested platform")
    package = matches[0]
    root = Path(package_root).resolve()
    archive_path = (root / Path(*PurePosixPath(package["path"]).parts)).resolve()
    try:
        archive_path.relative_to(root)
    except ValueError as exc:
        raise DocumentError("runtime package path escapes staging") from exc
    current = root
    for part in archive_path.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise DocumentError("runtime package path contains a symlink")
    if not archive_path.is_file() or archive_path.stat().st_size != package["size_bytes"]:
        raise DocumentError("runtime package is missing or has the wrong exact size")
    if sha256_file(archive_path) != package["sha256"]:
        raise DocumentError("runtime package SHA-256 mismatch")
    members = _members(archive_path, package["format"])
    if not members or len(members) > _MAX_ENTRIES:
        raise DocumentError("runtime archive entry count is outside the safe bound")
    names = [member.as_posix() for member, _, _, _ in members]
    if len(names) != len(set(names)):
        raise DocumentError("runtime archive contains duplicate member paths")
    expanded = sum(size for _, size, directory, _ in members if not directory)
    compressed = max(archive_path.stat().st_size, 1)
    if expanded > _MAX_EXPANDED_BYTES or expanded > compressed * _MAX_EXPANSION_RATIO:
        raise DocumentError("runtime archive expansion exceeds the safe bound")
    if package["executable_path"] not in names:
        raise DocumentError("runtime archive lacks the exact declared executable path")
    return {
        "schema_version": 1,
        "runtime_id": runtime["runtime_id"],
        "version": runtime["version"],
        "platform": platform,
        "package_sha256": package["sha256"],
        "executable_path": package["executable_path"],
        "entry_count": len(members),
        "static_archive_check": "pass",
        "executes_upstream_code": False,
    }


def extract_reviewed_llama_runtime(
    *, runtime_manifest_path: Path | str, package_root: Path | str,
    platform: str, repo_root: Path | str, destination: Path | str,
) -> Path:
    receipt = check_runtime_package(
        runtime_manifest_path=runtime_manifest_path, package_root=package_root,
        platform=platform, repo_root=repo_root,
    )
    if receipt["runtime_id"] != "llama.cpp-server":
        raise DocumentError("v1 automated evaluator executes only the pinned llama.cpp-server adapter")
    runtime = validate_runtime_manifest(runtime_manifest_path, repo_root, require_approved=False)
    package = next(item for item in runtime["packages"] if item["platform"] == platform)
    archive_path = Path(package_root).resolve() / Path(*PurePosixPath(package["path"]).parts)
    target = Path(destination).resolve()
    if target.exists() and any(target.iterdir()):
        raise DocumentError("runtime extraction destination must be fresh and empty")
    target.mkdir(parents=True, exist_ok=True)
    members = _members(archive_path, package["format"])
    member_map = {member.as_posix(): (size, directory, mode) for member, size, directory, mode in members}
    if package["format"] == "zip":
        with zipfile.ZipFile(archive_path) as archive:
            for item in archive.infolist():
                relative = _safe_member(item.filename)
                output = target / Path(*relative.parts)
                if item.is_dir():
                    output.mkdir(parents=True, exist_ok=True)
                else:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(item) as source, output.open("xb") as sink:
                        shutil.copyfileobj(source, sink)
                    mode = item.external_attr >> 16
                    if mode and os.name != "nt":
                        output.chmod(mode & 0o755)
    else:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for item in archive.getmembers():
                relative = _safe_member(item.name)
                output = target / Path(*relative.parts)
                if item.isdir():
                    output.mkdir(parents=True, exist_ok=True)
                    continue
                source = archive.extractfile(item)
                if source is None:
                    raise DocumentError(f"could not read runtime archive member {item.name}")
                output.parent.mkdir(parents=True, exist_ok=True)
                with source, output.open("xb") as sink:
                    shutil.copyfileobj(source, sink)
                if os.name != "nt":
                    output.chmod(item.mode & 0o755)
    executable = (target / Path(*PurePosixPath(package["executable_path"]).parts)).resolve()
    try:
        executable.relative_to(target)
    except ValueError as exc:
        raise DocumentError("declared runtime executable escapes extraction destination") from exc
    if not executable.is_file():
        raise DocumentError("declared runtime executable was not extracted as a regular file")
    return executable
