from __future__ import annotations

from pathlib import Path
import hashlib
import zipfile

import pytest

from conftest import build_candidate
from second_brain_models.errors import DocumentError
from second_brain_models.jsonio import load_json, write_canonical
from second_brain_models.runtime_archive import check_runtime_package, extract_reviewed_llama_runtime


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
