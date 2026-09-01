from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from second_brain_models.errors import PolicyError
from second_brain_models.policy import load_policy_bundle


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


def test_unknown_or_duplicate_policy_key_is_rejected(policy_repo: Path) -> None:
    path = policy_repo / "policy" / "upstream-allowlist.yaml"
    path.write_text(path.read_text(encoding="utf-8") + "\ndefault_decision: allow\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="duplicate"):
        load_policy_bundle(policy_repo)
