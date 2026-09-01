from __future__ import annotations

from pathlib import Path

import pytest

from conftest import build_candidate
from second_brain_models.candidate import check_candidate, validate_content_path
from second_brain_models.errors import DocumentError
from second_brain_models.jsonio import load_json, write_canonical
from second_brain_models.schema import validate_value


def test_exact_model_candidate_passes_without_executing_content(policy_repo: Path, tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    manifest, _, _ = build_candidate(policy_repo, staging)
    report = check_candidate(manifest, staging, policy_repo)
    assert report["static_format"] if "static_format" in report else report["checks"]["static_format"] == "pass"
    assert report["executes_upstream_code"] is False


@pytest.mark.parametrize("path", [
    "../models/sha256/" + "a" * 64 + "/model.gguf",
    "models\\sha256\\" + "a" * 64 + "\\model.gguf",
    "models/sha256/" + "a" * 64 + "/plugin.py",
])
def test_model_path_traversal_and_noncanonical_names_are_rejected(path: str) -> None:
    with pytest.raises(DocumentError):
        validate_content_path(path, "a" * 64)


def test_executable_magic_is_rejected_even_with_matching_digest(policy_repo: Path, tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    manifest_path, model_path, _ = build_candidate(policy_repo, staging)
    raw = b"MZ" + b"\0" * 30
    import hashlib

    digest = hashlib.sha256(raw).hexdigest()
    replacement = staging / "models" / "sha256" / digest / "model.gguf"
    replacement.parent.mkdir(parents=True)
    replacement.write_bytes(raw)
    model_path.unlink()
    manifest = load_json(manifest_path)
    manifest["artifact"].update({"path": f"models/sha256/{digest}/model.gguf", "sha256": digest, "size_bytes": len(raw)})
    write_canonical(manifest_path, manifest)
    with pytest.raises(DocumentError, match="executable"):
        check_candidate(manifest_path, staging, policy_repo)


def test_unexpected_companion_file_is_rejected(policy_repo: Path, tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    manifest, model, _ = build_candidate(policy_repo, staging)
    (model.parent / "plugin.py").write_text("raise SystemExit", encoding="utf-8")
    with pytest.raises(DocumentError, match="unexpected companion"):
        check_candidate(manifest, staging, policy_repo)


@pytest.mark.parametrize(("size_bytes", "tier"), [
    (1, "lite"),
    (1_999_999_999, "lite"),
    (2_000_000_000, "standard"),
    (5_999_999_999, "standard"),
    (6_000_000_000, "plus"),
])
def test_manifest_resource_tier_accepts_exact_size_boundaries(
    policy_repo: Path, tmp_path: Path, size_bytes: int, tier: str,
) -> None:
    manifest_path, _, _ = build_candidate(policy_repo, tmp_path / "staging")
    manifest = load_json(manifest_path)
    manifest["artifact"]["size_bytes"] = size_bytes
    manifest["tier"] = tier
    validate_value(manifest, "manifest", policy_repo)


@pytest.mark.parametrize(("size_bytes", "tier"), [
    (1_999_999_999, "standard"),
    (2_000_000_000, "lite"),
    (5_999_999_999, "plus"),
    (6_000_000_000, "standard"),
])
def test_manifest_resource_tier_rejects_wrong_size_band(
    policy_repo: Path, tmp_path: Path, size_bytes: int, tier: str,
) -> None:
    manifest_path, _, _ = build_candidate(policy_repo, tmp_path / "staging")
    manifest = load_json(manifest_path)
    manifest["artifact"]["size_bytes"] = size_bytes
    manifest["tier"] = tier
    with pytest.raises(DocumentError, match="manifest schema validation"):
        validate_value(manifest, "manifest", policy_repo)


def test_candidate_binds_declared_size_to_exact_staged_bytes(policy_repo: Path, tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    manifest_path, model_path, _ = build_candidate(policy_repo, staging)
    manifest = load_json(manifest_path)
    manifest["artifact"]["size_bytes"] = model_path.stat().st_size + 1
    write_canonical(manifest_path, manifest)
    with pytest.raises(DocumentError, match="artifact size mismatch"):
        check_candidate(manifest_path, staging, policy_repo)
