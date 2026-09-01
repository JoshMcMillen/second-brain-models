from __future__ import annotations

from pathlib import Path

import pytest

from conftest import build_candidate
from second_brain_models.errors import DocumentError
from second_brain_models.jsonio import load_json, write_canonical
from second_brain_models.runtime import validate_runtime_manifest


def test_quarantined_runtime_can_record_no_evidence_yet(policy_repo: Path, tmp_path: Path) -> None:
    _, _, runtime_path = build_candidate(policy_repo, tmp_path / "staging")
    runtime = load_json(runtime_path)
    runtime["no_egress_evidence"] = []
    write_canonical(runtime_path, runtime)

    validated = validate_runtime_manifest(runtime_path, policy_repo)
    assert validated["human_review"]["status"] == "candidate"
    assert validated["no_egress_evidence"] == []


def test_approved_runtime_cannot_omit_no_egress_evidence(policy_repo: Path, tmp_path: Path) -> None:
    _, _, runtime_path = build_candidate(policy_repo, tmp_path / "staging")
    runtime = load_json(runtime_path)
    runtime["human_review"] = {
        "required": True,
        "status": "approved",
        "review_reference": "owner-review-1",
    }
    runtime["no_egress_evidence"] = []
    write_canonical(runtime_path, runtime)

    with pytest.raises(DocumentError, match="schema validation"):
        validate_runtime_manifest(runtime_path, policy_repo)


def test_runtime_manifest_rejects_tampered_adjacent_license(policy_repo: Path, tmp_path: Path) -> None:
    _, _, runtime_path = build_candidate(policy_repo, tmp_path / "staging")
    (runtime_path.parent / "LICENSE").write_text("changed license bytes\n", encoding="utf-8")
    with pytest.raises(DocumentError, match="license SHA-256"):
        validate_runtime_manifest(runtime_path, policy_repo)
