from __future__ import annotations

import json
from pathlib import Path

from conftest import build_candidate
from second_brain_models.evaluation import (
    _quality_decision,
    evaluate_predictions,
    load_suite,
    validate_result_consistency,
)
from second_brain_models.errors import DocumentError, EvaluationError
from second_brain_models.runtime import validate_model_runtime_reference
import pytest
from second_brain_models.jsonio import load_json
from second_brain_models.policy import load_policy_bundle
from second_brain_models.schema import validate_value


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
    assert result["decision"]["eligible_task_contracts"] == [
        "grounded_summary-v1", "intent_routing-v1",
    ]
    assert result["execution"]["runtime_package_sha256"]
    assert result["execution"]["isolation"]["network_attempts_observed"] == 0
    assert "started_at" not in result["execution"]


def test_malformed_output_removes_only_the_affected_task(policy_repo: Path, tmp_path: Path) -> None:
    result = _run(policy_repo, tmp_path, corrupt_case="route_today_01")
    assert result["decision"]["promotion_recommendation"] == "stable"
    assert result["decision"]["eligible_task_contracts"] == ["grounded_summary-v1"]
    assert result["metrics"]["valid_typed_outputs"] == 29


def test_malformed_grounded_output_fails_without_false_semantic_labels(policy_repo: Path, tmp_path: Path) -> None:
    result = _run(policy_repo, tmp_path, corrupt_case="summary_project_09")
    assert result["metrics"]["valid_typed_outputs"] == 29
    assert result["metrics"]["silent_omissions"] == 0
    assert result["metrics"]["unsupported_claims"] == 0
    assert result["decision"]["promotion_recommendation"] == "stable"
    assert result["decision"]["eligible_task_contracts"] == ["intent_routing-v1"]


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
    assert result["decision"]["promotion_recommendation"] == "stable"
    assert result["decision"]["eligible_task_contracts"] == ["grounded_summary-v1"]


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
    assert result["decision"]["promotion_recommendation"] == "stable"
    assert result["decision"]["eligible_task_contracts"] == ["intent_routing-v1"]


def test_malformed_safety_output_fails_closed(policy_repo: Path, tmp_path: Path) -> None:
    result = _run(policy_repo, tmp_path, corrupt_case="injection_ignore_20")
    assert result["metrics"]["injection_obedience"] == 0
    assert result["metrics"]["safety_output_failures"] == 1
    assert result["decision"] == {
        "evaluation_status": "failed",
        "promotion_recommendation": "hold",
        "eligible_task_contracts": [],
        "human_approval_required": True,
    }


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
    assert result["decision"]["promotion_recommendation"] == "hold"
    assert result["decision"]["eligible_task_contracts"] == []


def test_standard_beta_boundary_allows_routing_only_profile(policy_repo: Path) -> None:
    promotion = load_policy_bundle(policy_repo)["promotion"]
    suite = load_suite(policy_repo / "evals" / "quality-v1.jsonl", promotion)
    rows = []
    category_seen: dict[str, int] = {}
    passing_by_category = {
        "instruction_typed_output": 8,
        "grounded_summarization": 4,
        "abstention": 3,
        "prompt_injection": 0,
        "authority_refusal": 6,
    }
    for case in suite:
        category = case["category"]
        index = category_seen.get(category, 0)
        category_seen[category] = index + 1
        flags = {
            "typed_output_valid": not (category == "abstention" and index >= 3),
            "unsupported_claim": category == "grounded_summarization" and index == 4,
            "silent_omission": category == "grounded_summarization" and index == 5,
            "injection_obedience": False,
            "authority_breach": False,
            "safety_output_failure": False,
        }
        rows.append({
            "case_id": case["case_id"],
            "passed": index < passing_by_category[category],
            "metric_flags": flags,
        })
    metrics = {
        "passed_cases": 21,
        "valid_typed_outputs": 28,
        "injection_obedience": 0,
        "authority_breaches": 0,
        "safety_output_failures": 0,
    }
    assert _quality_decision(metrics, rows, suite, "standard", promotion["evaluation"]) == (
        "beta", ["intent_routing-v1"],
    )


@pytest.mark.parametrize("tier", ["lite", "standard", "plus"])
def test_universal_safety_gates_precede_every_tier_quality(policy_repo: Path, tier: str) -> None:
    promotion = load_policy_bundle(policy_repo)["promotion"]
    suite = load_suite(policy_repo / "evals" / "quality-v1.jsonl", promotion)
    rows = [{
        "case_id": case["case_id"],
        "passed": True,
        "metric_flags": {
            "typed_output_valid": True,
            "unsupported_claim": False,
            "silent_omission": False,
            "injection_obedience": False,
            "authority_breach": case["case_id"] == "authority_approve_25",
            "safety_output_failure": case["case_id"] == "authority_approve_25",
        },
    } for case in suite]
    metrics = {
        "passed_cases": 30,
        "valid_typed_outputs": 30,
        "injection_obedience": 0,
        "authority_breaches": 1,
        "safety_output_failures": 1,
    }
    assert _quality_decision(metrics, rows, suite, tier, promotion["evaluation"]) == ("hold", [])


def test_result_schema_rejects_embedded_manifest_with_wrong_resource_tier(
    policy_repo: Path, tmp_path: Path,
) -> None:
    result = _run(policy_repo, tmp_path)
    result["subject"]["manifest"]["tier"] = "standard"
    with pytest.raises(DocumentError, match="result schema validation"):
        validate_value(result, "result", policy_repo)


@pytest.mark.parametrize(("recommendation", "status", "tasks"), [
    ("hold", "passed", []),
    ("hold", "failed", ["intent_routing-v1"]),
    ("beta", "failed", ["intent_routing-v1"]),
    ("stable", "passed", []),
])
def test_result_schema_rejects_inconsistent_promotion_decisions(
    policy_repo: Path,
    tmp_path: Path,
    recommendation: str,
    status: str,
    tasks: list[str],
) -> None:
    result = _run(policy_repo, tmp_path)
    result["decision"].update({
        "promotion_recommendation": recommendation,
        "evaluation_status": status,
        "eligible_task_contracts": tasks,
    })
    with pytest.raises(DocumentError, match="result schema validation"):
        validate_value(result, "result", policy_repo)


@pytest.mark.parametrize(("tier", "recommendation", "artifact_size"), [
    ("lite", "beta", 1),
    ("lite", "stable", 1),
    ("standard", "beta", 2_000_000_000),
    ("standard", "stable", 2_000_000_000),
    ("plus", "beta", 6_000_000_000),
    ("plus", "stable", 6_000_000_000),
])
def test_result_schema_enforces_tier_quality_floors(
    policy_repo: Path,
    tmp_path: Path,
    tier: str,
    recommendation: str,
    artifact_size: int,
) -> None:
    result = _run(policy_repo, tmp_path)
    thresholds = load_policy_bundle(policy_repo)["promotion"]["evaluation"]["tier_thresholds"][
        tier
    ][recommendation]
    result["subject"]["manifest"]["tier"] = tier
    result["subject"]["manifest"]["artifact"]["size_bytes"] = artifact_size
    result["decision"].update({
        "evaluation_status": "passed",
        "promotion_recommendation": recommendation,
        "eligible_task_contracts": ["intent_routing-v1"],
    })
    result["metrics"].update({
        "passed_cases": thresholds["minimum_passed_cases"],
        "valid_typed_outputs": thresholds["minimum_valid_typed_outputs"],
    })
    validate_value(result, "result", policy_repo)

    for metric in ("passed_cases", "valid_typed_outputs"):
        tampered = json.loads(json.dumps(result))
        tampered["metrics"][metric] -= 1
        with pytest.raises(DocumentError, match="result schema validation"):
            validate_value(tampered, "result", policy_repo)


@pytest.mark.parametrize("task_contract", ["grounded_answer-v1", "safety_boundary-v1"])
def test_result_schema_rejects_non_functional_eligible_task_contracts(
    policy_repo: Path, tmp_path: Path, task_contract: str,
) -> None:
    result = _run(policy_repo, tmp_path)
    result["decision"]["eligible_task_contracts"] = [task_contract]
    with pytest.raises(DocumentError, match="result schema validation"):
        validate_value(result, "result", policy_repo)


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


def test_eligible_task_contracts_are_recomputed_from_retained_outputs(
    policy_repo: Path, tmp_path: Path,
) -> None:
    result = _run(policy_repo, tmp_path)
    manifest = result["subject"]["manifest"]
    runtime = validate_model_runtime_reference(manifest, policy_repo)
    result["decision"]["eligible_task_contracts"].append("grounded_answer-v1")
    with pytest.raises(EvaluationError, match="deterministic policy thresholds"):
        validate_result_consistency(result, manifest, runtime, policy_repo)
