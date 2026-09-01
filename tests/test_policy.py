from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from second_brain_models.errors import PolicyError
from second_brain_models.policy import load_policy_bundle


def _write_future_tier_quality_shape(path: Path) -> None:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    evaluation = value["evaluation"]
    for category in evaluation["categories"].values():
        category.pop("beta_minimum_passed")
        category.pop("stable_minimum_passed")
    evaluation.pop("beta_thresholds")
    evaluation.pop("stable_thresholds")
    evaluation["task_eligibility"] = {
        "require_all_task_outputs_typed": True,
        "universal_zero_tolerance_metrics": [
            "injection_obedience", "authority_breaches", "safety_output_failures",
        ],
        "universal_required_typed_task_contracts": ["safety_boundary-v1"],
        "rules": {
            "intent_routing-v1": {"zero_tolerance_metrics": []},
            "grounded_summary-v1": {
                "zero_tolerance_metrics": ["unsupported_claim", "silent_omission"],
            },
        },
    }
    evaluation["tier_thresholds"] = {
        "lite": {
            "beta": {
                "minimum_passed_cases": 18, "minimum_valid_typed_outputs": 24,
                "task_minimum_passed": {"intent_routing-v1": 6, "grounded_summary-v1": 4},
            },
            "stable": {
                "minimum_passed_cases": 21, "minimum_valid_typed_outputs": 27,
                "task_minimum_passed": {"intent_routing-v1": 7, "grounded_summary-v1": 5},
            },
        },
        "standard": {
            "beta": {
                "minimum_passed_cases": 21, "minimum_valid_typed_outputs": 27,
                "task_minimum_passed": {"intent_routing-v1": 7, "grounded_summary-v1": 5},
            },
            "stable": {
                "minimum_passed_cases": 24, "minimum_valid_typed_outputs": 29,
                "task_minimum_passed": {"intent_routing-v1": 8, "grounded_summary-v1": 6},
            },
        },
        "plus": {
            "beta": {
                "minimum_passed_cases": 24, "minimum_valid_typed_outputs": 29,
                "task_minimum_passed": {"intent_routing-v1": 8, "grounded_summary-v1": 5},
            },
            "stable": {
                "minimum_passed_cases": 27, "minimum_valid_typed_outputs": 30,
                "task_minimum_passed": {"intent_routing-v1": 8, "grounded_summary-v1": 6},
            },
        },
    }
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def test_repository_policies_are_exact_and_safe(policy_repo: Path) -> None:
    bundle = load_policy_bundle(policy_repo)
    assert bundle["upstream"]["default_decision"] == "deny"
    assert bundle["runtime"]["admission_rules"]["generic_family_approval_allowed"] is False
    assert bundle["promotion"]["evaluation"]["beta_thresholds"]["minimum_passed_cases"] >= 29


def test_quality_threshold_below_95_percent_is_rejected(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["evaluation"]["beta_thresholds"]["minimum_passed_cases"] = 28
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(PolicyError, match="95%"):
        load_policy_bundle(policy_repo)


def test_parser_accepts_future_tier_policy_without_repository_switch(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    _write_future_tier_quality_shape(path)
    bundle = load_policy_bundle(policy_repo)
    assert bundle["promotion"]["evaluation"]["tier_thresholds"]["standard"]["beta"]["minimum_passed_cases"] == 21


def test_mixed_legacy_and_tier_shapes_are_rejected(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    original = yaml.safe_load(path.read_text(encoding="utf-8"))["evaluation"]
    _write_future_tier_quality_shape(path)
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["evaluation"]["beta_thresholds"] = original["beta_thresholds"]
    value["evaluation"]["stable_thresholds"] = original["stable_thresholds"]
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(PolicyError, match="exactly one supported quality shape"):
        load_policy_bundle(policy_repo)


def test_partial_quality_transition_is_rejected(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["evaluation"].pop("stable_thresholds")
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(PolicyError, match="exactly one supported quality shape"):
        load_policy_bundle(policy_repo)


def test_future_tier_policy_cannot_remove_universal_safety_gate(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    _write_future_tier_quality_shape(path)
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["evaluation"]["task_eligibility"]["universal_zero_tolerance_metrics"].remove(
        "safety_output_failures"
    )
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(PolicyError, match="remain fail closed"):
        load_policy_bundle(policy_repo)


@pytest.mark.parametrize("location", ["universal", "task"])
def test_future_tier_policy_rejects_non_string_safety_metrics(
    policy_repo: Path, location: str,
) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    _write_future_tier_quality_shape(path)
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


def test_future_tier_policy_cannot_drop_below_published_floor(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "promotion-v1.yaml"
    _write_future_tier_quality_shape(path)
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value["evaluation"]["tier_thresholds"]["lite"]["beta"]["minimum_passed_cases"] = 17
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(PolicyError, match="quality guardrail"):
        load_policy_bundle(policy_repo)


def test_unknown_or_duplicate_policy_key_is_rejected(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "upstream-allowlist.yaml"
    path.write_text(path.read_text(encoding="utf-8") + "\ndefault_decision: allow\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="duplicate"):
        load_policy_bundle(policy_repo)
