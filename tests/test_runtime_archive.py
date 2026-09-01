from __future__ import annotations

from pathlib import Path, PurePosixPath
import hashlib
import io
import stat
import tarfile
import zipfile

import pytest

from conftest import build_candidate
from second_brain_models.errors import DocumentError
from second_brain_models.jsonio import load_json, write_canonical
from second_brain_models.runtime_archive import (
    _resolved_tar_links,
    check_runtime_package,
    extract_reviewed_llama_runtime,
)


def _tar_file(archive: tarfile.TarFile, name: str, raw: bytes, *, mode: int = 0o644) -> None:
    item = tarfile.TarInfo(name)
    item.size = len(raw)
    item.mode = mode
    archive.addfile(item, io.BytesIO(raw))


def _tar_link(archive: tarfile.TarFile, name: str, target: str, *, hard: bool = False) -> None:
    item = tarfile.TarInfo(name)
    item.type = tarfile.LNKTYPE if hard else tarfile.SYMTYPE
    item.linkname = target
    item.mode = 0o777
    archive.addfile(item)


def _replace_fixture_runtime_with_tar(
    runtime_manifest: Path, staging: Path, archive_path: Path,
) -> None:
    runtime = load_json(runtime_manifest)
    package = runtime["packages"][0]
    old = staging / Path(*package["path"].split("/"))
    raw = archive_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    target = staging / "runtimes" / "sha256" / digest / "llama-linux-x86_64.tar.gz"
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    old.unlink()
    package.update({
        "upstream_url": "https://github.com/ggml-org/llama.cpp/releases/download/v1.2.3/llama-linux-x86_64.tar.gz",
        "url": f"https://models.avnxmcp.org/runtimes/sha256/{digest}/llama-linux-x86_64.tar.gz",
        "path": f"runtimes/sha256/{digest}/llama-linux-x86_64.tar.gz",
        "sha256": digest, "size_bytes": len(raw), "format": "tar.gz",
        "media_type": "application/gzip", "executable_path": "bin/llama-server",
    })
    runtime["no_egress_evidence"][0]["package_sha256"] = digest
    write_canonical(runtime_manifest, runtime)


def test_runtime_archive_is_verified_before_guarded_extraction(policy_repo: Path, tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    _, _, runtime_manifest = build_candidate(policy_repo, staging)
    report = check_runtime_package(runtime_manifest_path=runtime_manifest, package_root=staging, platform="linux-x86_64", repo_root=policy_repo)
    assert report["executes_upstream_code"] is False
    executable = extract_reviewed_llama_runtime(runtime_manifest_path=runtime_manifest, package_root=staging, platform="linux-x86_64", repo_root=policy_repo, destination=tmp_path / "fresh")
    assert executable.relative_to(tmp_path / "fresh").as_posix() == "bin/llama-server"


def test_runtime_archive_traversal_is_rejected_before_extraction(policy_repo: Path, tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    _, _, runtime_manifest = build_candidate(policy_repo, staging)
    runtime = load_json(runtime_manifest)
    old = staging / Path(*runtime["packages"][0]["path"].split("/"))
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as archive:
        archive.writestr("../escape", b"bad")
        archive.writestr("bin/llama-server", b"fixture")
    raw = bad.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    target = staging / "runtimes" / "sha256" / digest / "llama-linux-x86_64.zip"
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    old.unlink()
    package = runtime["packages"][0]
    package.update({"path": f"runtimes/sha256/{digest}/llama-linux-x86_64.zip", "url": f"https://models.avnxmcp.org/runtimes/sha256/{digest}/llama-linux-x86_64.zip", "sha256": digest, "size_bytes": len(raw)})
    runtime["no_egress_evidence"][0]["package_sha256"] = digest
    write_canonical(runtime_manifest, runtime)
    with pytest.raises(DocumentError, match="unsafe"):
        check_runtime_package(runtime_manifest_path=runtime_manifest, package_root=staging, platform="linux-x86_64", repo_root=policy_repo)


def test_safe_tar_link_chains_are_materialized_as_regular_files(policy_repo: Path, tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    _, _, runtime_manifest = build_candidate(policy_repo, staging)
    archive_path = tmp_path / "runtime.tar.gz"
    library = b"reviewed shared library bytes"
    with tarfile.open(archive_path, "w:gz") as archive:
        _tar_file(archive, "bin/llama-server", b"reviewed runtime fixture", mode=0o755)
        _tar_file(archive, "lib/libfixture.so.1", library, mode=0o755)
        _tar_link(archive, "lib/libfixture.so.0", "libfixture.so.1")
        _tar_link(archive, "lib/libfixture.so", "libfixture.so.0")
    _replace_fixture_runtime_with_tar(runtime_manifest, staging, archive_path)

    report = check_runtime_package(
        runtime_manifest_path=runtime_manifest, package_root=staging,
        platform="linux-x86_64", repo_root=policy_repo,
    )
    assert report["materialized_alias_count"] == 2
    assert report["materialized_alias_bytes"] == 2 * len(library)

    destination = tmp_path / "extracted"
    extract_reviewed_llama_runtime(
        runtime_manifest_path=runtime_manifest, package_root=staging,
        platform="linux-x86_64", repo_root=policy_repo, destination=destination,
    )
    for name in ("libfixture.so.0", "libfixture.so"):
        alias = destination / "lib" / name
        assert alias.is_file()
        assert not alias.is_symlink()
        assert alias.read_bytes() == library


@pytest.mark.parametrize(("target", "message"), [
    ("../escape", "unsafe"),
    ("/absolute/escape", "unsafe"),
    ("missing.so", "missing"),
])
def test_unsafe_or_missing_tar_link_is_rejected(
    policy_repo: Path, tmp_path: Path, target: str, message: str,
) -> None:
    staging = tmp_path / "staging"
    _, _, runtime_manifest = build_candidate(policy_repo, staging)
    archive_path = tmp_path / "runtime.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        _tar_file(archive, "bin/llama-server", b"reviewed runtime fixture", mode=0o755)
        _tar_link(archive, "lib/libfixture.so", target)
    _replace_fixture_runtime_with_tar(runtime_manifest, staging, archive_path)
    with pytest.raises(DocumentError, match=message):
        check_runtime_package(
            runtime_manifest_path=runtime_manifest, package_root=staging,
            platform="linux-x86_64", repo_root=policy_repo,
        )


def test_tar_link_cycle_is_rejected(policy_repo: Path, tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    _, _, runtime_manifest = build_candidate(policy_repo, staging)
    archive_path = tmp_path / "runtime.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        _tar_file(archive, "bin/llama-server", b"reviewed runtime fixture", mode=0o755)
        _tar_link(archive, "lib/a.so", "b.so")
        _tar_link(archive, "lib/b.so", "a.so")
    _replace_fixture_runtime_with_tar(runtime_manifest, staging, archive_path)
    with pytest.raises(DocumentError, match="cycle"):
        check_runtime_package(
            runtime_manifest_path=runtime_manifest, package_root=staging,
            platform="linux-x86_64", repo_root=policy_repo,
        )


def test_maximum_length_tar_link_chain_is_resolved_linearly() -> None:
    final_target = PurePosixPath("lib/final.so")
    members = []
    for index in range(20_000):
        member = PurePosixPath(f"lib/alias-{index:05d}.so")
        target = final_target if index == 19_999 else PurePosixPath(f"lib/alias-{index + 1:05d}.so")
        members.append((member, 0, False, 0o777, target))
    members.append((final_target, 1, False, 0o755, None))
    resolved = _resolved_tar_links(members)
    assert len(resolved) == 20_000
    assert set(resolved.values()) == {final_target}


def test_tar_hard_link_and_zip_symlink_remain_forbidden(policy_repo: Path, tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    _, _, runtime_manifest = build_candidate(policy_repo, staging)
    archive_path = tmp_path / "runtime.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        _tar_file(archive, "bin/llama-server", b"reviewed runtime fixture", mode=0o755)
        _tar_link(archive, "bin/alias", "bin/llama-server", hard=True)
    _replace_fixture_runtime_with_tar(runtime_manifest, staging, archive_path)
    with pytest.raises(DocumentError, match="hard link"):
        check_runtime_package(
            runtime_manifest_path=runtime_manifest, package_root=staging,
            platform="linux-x86_64", repo_root=policy_repo,
        )

    staging = tmp_path / "zip-staging"
    _, _, runtime_manifest = build_candidate(policy_repo, staging)
    runtime = load_json(runtime_manifest)
    package = runtime["packages"][0]
    original = staging / Path(*package["path"].split("/"))
    bad_zip = tmp_path / "symlink.zip"
    with zipfile.ZipFile(bad_zip, "w") as archive:
        executable = zipfile.ZipInfo("bin/llama-server")
        executable.external_attr = 0o100755 << 16
        archive.writestr(executable, b"reviewed runtime fixture")
        alias = zipfile.ZipInfo("bin/alias")
        alias.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(alias, "llama-server")
    raw = bad_zip.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    replacement = staging / "runtimes" / "sha256" / digest / "llama-linux-x86_64.zip"
    replacement.parent.mkdir(parents=True)
    replacement.write_bytes(raw)
    original.unlink()
    package.update({
        "path": f"runtimes/sha256/{digest}/llama-linux-x86_64.zip",
        "url": f"https://models.avnxmcp.org/runtimes/sha256/{digest}/llama-linux-x86_64.zip",
        "sha256": digest, "size_bytes": len(raw),
    })
    runtime["no_egress_evidence"][0]["package_sha256"] = digest
    write_canonical(runtime_manifest, runtime)
    with pytest.raises(DocumentError, match="symlink"):
        check_runtime_package(
            runtime_manifest_path=runtime_manifest, package_root=staging,
            platform="linux-x86_64", repo_root=policy_repo,
        )
