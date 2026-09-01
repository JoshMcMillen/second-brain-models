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


def _run(
    policy_repo: Path,
    tmp_path: Path,
    *,
    corrupt_case: str | None = None,
    replacement_case: str | None = None,
    replacement_output: dict | None = None,
):
    staging = tmp_path / "staging"
    manifest_path, _, runtime_path = build_candidate(policy_repo, staging)
    suite = load_suite(policy_repo / "evals" / "quality-v1.jsonl", load_policy_bundle(policy_repo)["promotion"])
    predictions = tmp_path / "predictions.jsonl"
    with predictions.open("w", encoding="utf-8", newline="\n") as handle:
        for case in suite:
            if case["case_id"] == corrupt_case:
                output_text = "not-json"
            elif case["case_id"] == replacement_case:
                output_text = json.dumps(replacement_output, separators=(",", ":"))
            else:
                output_text = json.dumps(_golden(case), separators=(",", ":"))
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


def test_malformed_grounded_output_fails_without_false_semantic_labels(policy_repo: Path, tmp_path: Path) -> None:
    result = _run(policy_repo, tmp_path, corrupt_case="summary_project_09")
    assert result["metrics"]["valid_typed_outputs"] == 29
    assert result["metrics"]["silent_omissions"] == 0
    assert result["metrics"]["unsupported_claims"] == 0
    assert result["decision"]["promotion_recommendation"] == "hold"


def test_typed_metric_rejects_correct_keys_with_wrong_value_type(policy_repo: Path, tmp_path: Path) -> None:
    replacement = {
        "schema_version": 1,
        "route": "today",
        "confidence": "high",
        "reason": "fixture",
    }
    result = _run(
        policy_repo,
        tmp_path,
        replacement_case="route_today_01",
        replacement_output=replacement,
    )
    assert result["metrics"]["passed_cases"] == 29
    assert result["metrics"]["valid_typed_outputs"] == 29
    assert result["decision"]["promotion_recommendation"] == "hold"


def test_boolean_does_not_equal_json_integer(policy_repo: Path, tmp_path: Path) -> None:
    replacement = {
        "schema_version": True,
        "route": "today",
        "confidence": 0.5,
        "reason": "fixture",
    }
    result = _run(
        policy_repo,
        tmp_path,
        replacement_case="route_today_01",
        replacement_output=replacement,
    )
    row = next(item for item in result["case_results"] if item["case_id"] == "route_today_01")
    assert row["check_results"]["check_02_field_equals"] is False
    assert row["metric_flags"]["typed_output_valid"] is False


def test_typed_metric_enforces_ranges_and_lengths(policy_repo: Path, tmp_path: Path) -> None:
    replacement = {
        "schema_version": 1,
        "route": "today",
        "confidence": 2,
        "reason": "",
    }
    result = _run(
        policy_repo,
        tmp_path,
        replacement_case="route_today_01",
        replacement_output=replacement,
    )
    row = next(item for item in result["case_results"] if item["case_id"] == "route_today_01")
    assert row["check_results"]["check_05_number_range"] is False
    assert row["check_results"]["check_07_string_length"] is False
    assert row["metric_flags"]["typed_output_valid"] is False


def test_selected_summary_sentence_omission_is_a_hard_failure(policy_repo: Path, tmp_path: Path) -> None:
    replacement = {
        "schema_version": 1,
        "selected_fact_ids": ["f1", "f2"],
        "summary": "Project Atlas is in planning.",
    }
    result = _run(
        policy_repo,
        tmp_path,
        replacement_case="summary_project_09",
        replacement_output=replacement,
    )
    assert result["metrics"]["passed_cases"] == 29
    assert result["metrics"]["valid_typed_outputs"] == 30
    assert result["metrics"]["silent_omissions"] == 1
    assert result["decision"]["promotion_recommendation"] == "hold"


def test_metric_flag_tampering_cannot_convert_hold_to_stable(policy_repo: Path, tmp_path: Path) -> None:
    replacement = {
        "schema_version": 1,
        "route": "today",
        "confidence": "high",
        "reason": "fixture",
    }
    result = _run(
        policy_repo,
        tmp_path,
        replacement_case="route_today_01",
        replacement_output=replacement,
    )
    manifest = result["subject"]["manifest"]
    runtime = validate_model_runtime_reference(manifest, policy_repo)
    row = next(item for item in result["case_results"] if item["case_id"] == "route_today_01")
    row["metric_flags"]["typed_output_valid"] = True
    result["metrics"]["valid_typed_outputs"] = 30
    result["decision"] = {
        "evaluation_status": "passed",
        "promotion_recommendation": "stable",
        "human_approval_required": True,
    }
    with pytest.raises(EvaluationError, match="metric_flags differs from retained output"):
        validate_result_consistency(result, manifest, runtime, policy_repo)


def test_silent_omission_flag_cannot_be_erased(policy_repo: Path, tmp_path: Path) -> None:
    replacement = {
        "schema_version": 1,
        "selected_fact_ids": ["f1", "f2"],
        "summary": "Project Atlas is in planning.",
    }
    result = _run(
        policy_repo,
        tmp_path,
        replacement_case="summary_project_09",
        replacement_output=replacement,
    )
    manifest = result["subject"]["manifest"]
    runtime = validate_model_runtime_reference(manifest, policy_repo)
    row = next(item for item in result["case_results"] if item["case_id"] == "summary_project_09")
    row["metric_flags"]["silent_omission"] = False
    result["metrics"]["silent_omissions"] = 0
    result["decision"] = {
        "evaluation_status": "passed",
        "promotion_recommendation": "stable",
        "human_approval_required": True,
    }
    with pytest.raises(EvaluationError, match="metric_flags differs from retained output"):
        validate_result_consistency(result, manifest, runtime, policy_repo)


def test_explicit_unsafe_decision_is_flagged_despite_unrelated_type_error(
    policy_repo: Path, tmp_path: Path,
) -> None:
    replacement = {
        "schema_version": 1,
        "decision": "execute",
        "reason_code": "prompt_injection",
        "route": 7,
    }
    result = _run(
        policy_repo,
        tmp_path,
        replacement_case="injection_ignore_20",
        replacement_output=replacement,
    )
    row = next(item for item in result["case_results"] if item["case_id"] == "injection_ignore_20")
    assert row["metric_flags"]["typed_output_valid"] is False
    assert row["metric_flags"]["injection_obedience"] is True
    assert result["metrics"]["injection_obedience"] == 1


def test_output_text_and_digest_are_bound(policy_repo: Path, tmp_path: Path) -> None:
    result = _run(policy_repo, tmp_path)
    manifest = result["subject"]["manifest"]
    runtime = validate_model_runtime_reference(manifest, policy_repo)
    result["case_results"][0]["output_text"] += " "
    with pytest.raises(EvaluationError, match="output digest differs"):
        validate_result_consistency(result, manifest, runtime, policy_repo)


def test_forged_check_name_cannot_inflate_result(policy_repo: Path, tmp_path: Path) -> None:
    result = _run(policy_repo, tmp_path)
    manifest = result["subject"]["manifest"]
    runtime = validate_model_runtime_reference(manifest, policy_repo)
    result["case_results"][0]["check_results"] = {"fake_json_exact_keys": True}
    with pytest.raises(EvaluationError, match="check_results differs from retained output"):
        validate_result_consistency(result, manifest, runtime, policy_repo)
