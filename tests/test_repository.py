from __future__ import annotations

from pathlib import Path

import pytest

from conftest import build_candidate
from second_brain_models.errors import DocumentError, PolicyError
from second_brain_models.repository import check_repository


REPO_ROOT = Path(__file__).resolve().parents[1]


def external_staging(policy_repo: Path) -> Path:
    return policy_repo.parent / f"{policy_repo.name}-external-staging"


def test_git_preserves_exact_upstream_license_bytes() -> None:
    attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "LICENSE -text diff whitespace=cr-at-eol" in attributes.splitlines()
    assert "NOTICE -text diff whitespace=cr-at-eol" in attributes.splitlines()
    assert "LICENSE text eol=lf" not in attributes.splitlines()
    assert "NOTICE text eol=lf" not in attributes.splitlines()


def test_repo_check_validates_actual_model_and_runtime_documents(policy_repo: Path, tmp_path: Path) -> None:
    build_candidate(policy_repo, external_staging(policy_repo))
    receipt = check_repository(policy_repo)
    assert receipt["validated"]["manifest"] == 1
    assert receipt["validated"]["runtime"] == 1


def test_repo_check_fails_on_invalid_actual_document(policy_repo: Path, tmp_path: Path) -> None:
    manifest, _, _ = build_candidate(policy_repo, external_staging(policy_repo))
    manifest.write_text("{}\n", encoding="utf-8")
    with pytest.raises(DocumentError, match="schema validation"):
        check_repository(policy_repo)


def test_repo_check_rejects_cross_field_runtime_drift(policy_repo: Path, tmp_path: Path) -> None:
    _, _, runtime_path = build_candidate(policy_repo, external_staging(policy_repo))
    import json

    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    runtime["upstream"]["repository"] = "github.com/ollama/ollama"
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")
    with pytest.raises(PolicyError, match="differs from the allowlist"):
        check_repository(policy_repo)


def test_repo_check_rejects_tampered_adjacent_model_license(policy_repo: Path, tmp_path: Path) -> None:
    manifest, _, _ = build_candidate(policy_repo, external_staging(policy_repo))
    (manifest.parent / "LICENSE").write_text("changed license bytes\n", encoding="utf-8")
    with pytest.raises(DocumentError, match="license SHA-256"):
        check_repository(policy_repo)


def test_repo_check_rejects_floating_external_score(policy_repo: Path, tmp_path: Path) -> None:
    manifest_path, _, _ = build_candidate(policy_repo, external_staging(policy_repo))
    import json

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["external_quality_evidence"][0]["score"] = 0.9
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(DocumentError, match="schema validation"):
        check_repository(policy_repo)


@pytest.mark.parametrize("payload,name", [
    (b"GGUF" + b"x" * 32, "model.gguf"),
    (("ghp_" + "a" * 30).encode(), "notes.txt"),
    (("-----BEGIN " + "PRIVATE KEY-----").encode(), "oops.pem"),
])
def test_repo_check_rejects_binary_or_secret_material(policy_repo: Path, payload: bytes, name: str) -> None:
    (policy_repo / name).write_bytes(payload)
    with pytest.raises(DocumentError, match="forbidden"):
        check_repository(policy_repo)
