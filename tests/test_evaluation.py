from __future__ import annotations

import json
from pathlib import Path

from conftest import build_candidate
from second_brain_models.evaluation import evaluate_predictions, load_suite, validate_result_consistency
from second_brain_models.errors import EvaluationError
from second_brain_models.runtime import validate_model_runtime_reference
import pytest
from second_brain_models.jsonio import load_json
from second_brain_models.policy import load_policy_bundle


def _golden(case: dict) -> dict:
    exact = next(check["value"] for check in case["expected_checks"] if check["op"] == "json_exact_keys")
    output = {key: None for key in exact}
    for check in case["expected_checks"]:
        if check["op"] in {"field_equals", "array_equals"}:
            output[check["path"].lstrip("/")] = check["value"]
        elif check["op"] == "field_type":
            key = check["path"].lstrip("/")
            if output[key] is None:
                output[key] = {"number": 0.5, "string": "fixture"}[check["value"]]
    return output


def _evidence() -> dict:
    return {
        "network_mode": "none", "dns_resolution_available": False,
        "outbound_connectivity_available": False, "default_route_present": False,
        "loopback_runtime_reachable": True, "monitor_method": "strace-network-syscalls",
        "monitor_started_before_runtime": True, "attempted_dns": 0, "attempted_tcp": 0,
        "attempted_udp": 0, "network_attempts_observed": 0,
        "monitor_evidence_sha256": "d" * 64, "verified_at": "2026-09-01T12:04:00Z",
        "isolation_id": "fixture-evaluation-1",
    }


def _run(policy_repo: Path, tmp_path: Path, *, corrupt_case: str | None = None):
    staging = tmp_path / "staging"
    manifest_path, _, runtime_path = build_candidate(policy_repo, staging)
    suite = load_suite(policy_repo / "evals" / "quality-v1.jsonl", load_policy_bundle(policy_repo)["promotion"])
    predictions = tmp_path / "predictions.jsonl"
    with predictions.open("w", encoding="utf-8", newline="\n") as handle:
        for case in suite:
            output_text = "not-json" if case["case_id"] == corrupt_case else json.dumps(_golden(case), separators=(",", ":"))
            handle.write(json.dumps({"case_id": case["case_id"], "output_text": output_text}, separators=(",", ":")) + "\n")
    runtime = load_json(runtime_path)
    package = runtime["packages"][0]
    return evaluate_predictions(
        repo_root=policy_repo, manifest_path=manifest_path, predictions_path=predictions,
        output_path=tmp_path / "result.json", runner_id="fixture-runner", runner_version="1.0.0",
        runtime_version=runtime["version"], runtime_platform=package["platform"],
        runtime_package_sha256=package["sha256"],
        isolation_id="fixture-evaluation-1", isolation_evidence=_evidence(),
        runtime_started_at="2026-09-01T12:00:00Z", inference_started_at="2026-09-01T12:01:00Z",
        inference_finished_at="2026-09-01T12:03:00Z", runtime_finished_at="2026-09-01T12:04:00Z",
    )


def test_exact_synthetic_outputs_reach_stable_gate_and_bind_runtime(policy_repo: Path, tmp_path: Path) -> None:
    result = _run(policy_repo, tmp_path)
    assert result["metrics"]["passed_cases"] == 30
    assert result["decision"]["promotion_recommendation"] == "stable"
    assert result["execution"]["runtime_package_sha256"]
    assert result["execution"]["isolation"]["network_attempts_observed"] == 0
    assert "started_at" not in result["execution"]


def test_malformed_slop_output_fails_promotion(policy_repo: Path, tmp_path: Path) -> None:
    result = _run(policy_repo, tmp_path, corrupt_case="route_today_01")
    assert result["decision"] == {
        "evaluation_status": "failed", "promotion_recommendation": "hold", "human_approval_required": True,
    }
    assert result["metrics"]["valid_typed_outputs"] == 29


def test_malformed_grounded_output_counts_as_silent_omission(policy_repo: Path, tmp_path: Path) -> None:
    result = _run(policy_repo, tmp_path, corrupt_case="summary_project_09")
    assert result["metrics"]["silent_omissions"] == 1
    assert result["decision"]["promotion_recommendation"] == "hold"


def test_forged_check_name_cannot_inflate_result(policy_repo: Path, tmp_path: Path) -> None:
    result = _run(policy_repo, tmp_path)
    manifest = result["subject"]["manifest"]
    runtime = validate_model_runtime_reference(manifest, policy_repo)
    result["case_results"][0]["check_results"] = {"fake_json_exact_keys": True}
    with pytest.raises(EvaluationError, match="check set differs"):
        validate_result_consistency(result, manifest, runtime, policy_repo)
