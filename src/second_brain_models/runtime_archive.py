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
_ArchiveMember = tuple[PurePosixPath, int, bool, int, PurePosixPath | None]


def _safe_member(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name:
        raise DocumentError("runtime archive member uses an unsafe path encoding")
    path = PurePosixPath(name.rstrip("/"))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        raise DocumentError(f"runtime archive member path is unsafe: {name!r}")
    return path


def _zip_members(path: Path) -> list[_ArchiveMember]:
    try:
        with zipfile.ZipFile(path) as archive:
            result = []
            for item in archive.infolist():
                mode = item.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if stat.S_ISLNK(mode) or file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise DocumentError(f"runtime ZIP contains symlink or special entry: {item.filename}")
                result.append((_safe_member(item.filename), item.file_size, item.is_dir(), mode, None))
            return result
    except (OSError, zipfile.BadZipFile) as exc:
        raise DocumentError(f"invalid runtime ZIP: {exc}") from exc


def _safe_tar_link_target(member: PurePosixPath, value: str) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value:
        raise DocumentError(f"runtime tar symlink target is unsafe: {value!r}")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} or ":" in part for part in raw_parts):
        raise DocumentError(f"runtime tar symlink target is unsafe: {value!r}")
    target = PurePosixPath(value)
    if target.is_absolute() or not target.parts:
        raise DocumentError(f"runtime tar symlink target is unsafe: {value!r}")
    return member.parent / target


def _tar_members(path: Path) -> list[_ArchiveMember]:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            result = []
            for item in archive.getmembers():
                member = _safe_member(item.name)
                if item.issym():
                    if item.size != 0:
                        raise DocumentError(f"runtime tar symlink has unexpected data: {item.name}")
                    result.append((
                        member, 0, False, item.mode,
                        _safe_tar_link_target(member, item.linkname),
                    ))
                    continue
                if not (item.isfile() or item.isdir()) or item.islnk() or item.isdev():
                    raise DocumentError(f"runtime tar contains hard link or special entry: {item.name}")
                result.append((member, item.size, item.isdir(), item.mode, None))
            return result
    except (OSError, tarfile.TarError) as exc:
        raise DocumentError(f"invalid runtime tar.gz: {exc}") from exc


def _members(path: Path, format_name: str) -> list[_ArchiveMember]:
    if format_name == "zip":
        return _zip_members(path)
    if format_name == "tar.gz":
        return _tar_members(path)
    raise DocumentError(f"runtime package format {format_name!r} is not supported by the guarded v1 extractor")


def _resolved_tar_links(members: list[_ArchiveMember]) -> dict[PurePosixPath, PurePosixPath]:
    """Resolve safe in-archive symlink chains to exact regular file members."""
    member_map = {member: (size, directory, mode, link) for member, size, directory, mode, link in members}
    resolved: dict[PurePosixPath, PurePosixPath] = {}
    for member, _, _, _, link in members:
        if link is None or member in resolved:
            continue
        origin = member
        trail: list[PurePosixPath] = []
        visiting: set[PurePosixPath] = set()
        current = member
        while True:
            known = resolved.get(current)
            if known is not None:
                final_target = known
                break
            if current in visiting:
                raise DocumentError(f"runtime tar symlink cycle is forbidden: {origin.as_posix()}")
            visiting.add(current)
            target = member_map.get(current)
            if target is None:
                raise DocumentError(f"runtime tar symlink target is missing: {origin.as_posix()}")
            _, directory, _, next_link = target
            if directory:
                raise DocumentError(f"runtime tar symlink to a directory is forbidden: {origin.as_posix()}")
            if next_link is None:
                final_target = current
                break
            trail.append(current)
            current = next_link
        for alias in trail:
            resolved[alias] = final_target
    return resolved


def _validate_member_tree(members: list[_ArchiveMember]) -> None:
    member_map = {member: (directory, link) for member, _, directory, _, link in members}
    for member, _, _, _, _ in members:
        for ancestor in member.parents:
            if ancestor == PurePosixPath("."):
                continue
            ancestor_entry = member_map.get(ancestor)
            if ancestor_entry is not None and not ancestor_entry[0]:
                raise DocumentError(
                    f"runtime archive uses a non-directory member as a path ancestor: {ancestor.as_posix()}"
                )


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
    names = [member.as_posix() for member, _, _, _, _ in members]
    if len(names) != len(set(names)):
        raise DocumentError("runtime archive contains duplicate member paths")
    _validate_member_tree(members)
    member_map = {member: (size, directory, mode, link) for member, size, directory, mode, link in members}
    resolved_links = _resolved_tar_links(members)
    expanded = sum(
        size for _, size, directory, _, link in members if not directory and link is None
    )
    materialized_alias_bytes = sum(member_map[target][0] for target in resolved_links.values())
    expanded += materialized_alias_bytes
    compressed = max(archive_path.stat().st_size, 1)
    if expanded > _MAX_EXPANDED_BYTES or expanded > compressed * _MAX_EXPANSION_RATIO:
        raise DocumentError("runtime archive expansion exceeds the safe bound")
    executable_member = PurePosixPath(package["executable_path"])
    executable_entry = member_map.get(executable_member)
    if executable_entry is None or executable_entry[1] or executable_entry[3] is not None:
        raise DocumentError("runtime archive lacks the exact declared executable path")
    return {
        "schema_version": 1,
        "runtime_id": runtime["runtime_id"],
        "version": runtime["version"],
        "platform": platform,
        "package_sha256": package["sha256"],
        "executable_path": package["executable_path"],
        "entry_count": len(members),
        "materialized_alias_count": len(resolved_links),
        "materialized_alias_bytes": materialized_alias_bytes,
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
    member_map = {
        member: (size, directory, mode, link)
        for member, size, directory, mode, link in members
    }
    resolved_links = _resolved_tar_links(members)
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
                if item.issym():
                    continue
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
                if output.stat().st_size != member_map[relative][0]:
                    raise DocumentError(f"runtime tar member size changed during extraction: {item.name}")
                if os.name != "nt":
                    output.chmod(item.mode & 0o755)
        for alias, final_target in resolved_links.items():
            source = target / Path(*final_target.parts)
            output = target / Path(*alias.parts)
            if source.is_symlink() or not source.is_file() or output.exists() or output.is_symlink():
                raise DocumentError(f"could not safely materialize runtime tar alias {alias.as_posix()}")
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, output)
            if output.stat().st_size != member_map[final_target][0]:
                raise DocumentError(f"runtime tar alias size changed during materialization: {alias.as_posix()}")
            if os.name != "nt":
                output.chmod(member_map[final_target][2] & 0o755)
    executable = (target / Path(*PurePosixPath(package["executable_path"]).parts)).resolve()
    try:
        executable.relative_to(target)
    except ValueError as exc:
        raise DocumentError("declared runtime executable escapes extraction destination") from exc
    if not executable.is_file():
        raise DocumentError("declared runtime executable was not extracted as a regular file")
    return executable
