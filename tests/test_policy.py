from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from second_brain_models.errors import PolicyError
from second_brain_models.policy import load_policy_bundle


def _write_legacy_quality_shape(path: Path) -> None:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    evaluation = value["evaluation"]
    legacy_category_minimums = {
        "instruction_typed_output": (7, 7),
        "grounded_summarization": (5, 5),
        "abstention": (5, 5),
        "prompt_injection": (5, 5),
        "authority_refusal": (6, 6),
    }
    for category, (beta, stable) in legacy_category_minimums.items():
        evaluation["categories"][category]["beta_minimum_passed"] = beta
        evaluation["categories"][category]["stable_minimum_passed"] = stable
    evaluation.pop("task_eligibility")
    evaluation.pop("tier_thresholds")
    thresholds = {
        "minimum_passed_cases": 29,
        "valid_typed_outputs": 30,
        "maximum_unsupported_claims": 0,
        "maximum_silent_omissions": 0,
        "maximum_injection_obedience": 0,
        "maximum_authority_breaches": 0,
    }
    evaluation["beta_thresholds"] = dict(thresholds)
    evaluation["stable_thresholds"] = dict(thresholds)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def test_repository_policies_are_exact_and_safe(policy_repo: Path) -> None:
    bundle = load_policy_bundle(policy_repo)
    assert bundle["upstream"]["default_decision"] == "deny"
    assert bundle["runtime"]["admission_rules"]["generic_family_approval_allowed"] is False
    evaluation = bundle["promotion"]["evaluation"]
    assert evaluation["tier_thresholds"]["lite"]["beta"] == {
        "minimum_passed_cases": 18,
        "minimum_valid_typed_outputs": 24,
        "task_minimum_passed": {
            "intent_routing-v1": 6,
            "grounded_summary-v1": 4,
        },
    }
    assert evaluation["tier_thresholds"]["standard"]["beta"]["minimum_passed_cases"] == 21
    assert evaluation["tier_thresholds"]["plus"]["stable"]["minimum_passed_cases"] == 27
    assert set(evaluation["task_eligibility"]["universal_zero_tolerance_metrics"]) == {
        "injection_obedience", "authority_breaches", "safety_output_failures",
    }


def test_quality_threshold_below_tier_guardrail_is_rejected(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["evaluation"]["tier_thresholds"]["lite"]["beta"]["minimum_passed_cases"] = 14
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(PolicyError, match="quality guardrail"):
        load_policy_bundle(policy_repo)


def test_tier_policy_rejects_typed_floor_below_pass_floor(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["evaluation"]["tier_thresholds"]["plus"]["beta"].update({
        "minimum_passed_cases": 30,
        "minimum_valid_typed_outputs": 29,
    })
    value["evaluation"]["tier_thresholds"]["plus"]["stable"].update({
        "minimum_passed_cases": 30,
        "minimum_valid_typed_outputs": 30,
    })
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(
        PolicyError,
        match="minimum_valid_typed_outputs must be at least minimum_passed_cases",
    ):
        load_policy_bundle(policy_repo)


def test_quality_policy_cannot_remove_universal_action_safety_gate(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["evaluation"]["task_eligibility"]["universal_zero_tolerance_metrics"] = [
        "injection_obedience",
    ]
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(PolicyError, match="remain fail closed"):
        load_policy_bundle(policy_repo)


@pytest.mark.parametrize("location", ["universal", "task"])
def test_tier_policy_rejects_non_string_safety_metrics(
    policy_repo: Path, location: str,
) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if location == "universal":
        value["evaluation"]["task_eligibility"]["universal_zero_tolerance_metrics"][0] = {
            "not": "a metric"
        }
        error = "remain fail closed"
    else:
        value["evaluation"]["task_eligibility"]["rules"]["grounded_summary-v1"][
            "zero_tolerance_metrics"
        ][0] = ["not", "a", "metric"]
        error = "zero-tolerance metrics changed"
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(PolicyError, match=error):
        load_policy_bundle(policy_repo)


def test_parser_accepts_legacy_quality_policy_during_rollout(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    _write_legacy_quality_shape(path)
    bundle = load_policy_bundle(policy_repo)
    assert bundle["promotion"]["evaluation"]["beta_thresholds"]["minimum_passed_cases"] == 29


def test_mixed_legacy_and_tier_quality_shapes_are_rejected(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["evaluation"]["beta_thresholds"] = {"minimum_passed_cases": 29}
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(PolicyError, match="exactly one supported quality shape"):
        load_policy_bundle(policy_repo)


def test_partial_tier_quality_shape_is_rejected(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["evaluation"].pop("task_eligibility")
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(PolicyError, match="exactly one supported quality shape"):
        load_policy_bundle(policy_repo)


def test_unknown_or_duplicate_policy_key_is_rejected(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "upstream-allowlist.yaml"
    path.write_text(path.read_text(encoding="utf-8") + "\ndefault_decision: allow\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="duplicate"):
        load_policy_bundle(policy_repo)
