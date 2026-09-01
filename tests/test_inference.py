from __future__ import annotations

import pytest

from second_brain_models.errors import EvaluationError
from second_brain_models.inference import _contract_instruction


@pytest.mark.parametrize(
    ("contract", "required_terms"),
    [
        ("intent_routing-v1", ("allowed_routes", "confidence", "reason")),
        ("grounded_summary-v1", ("selected_fact_ids", "extractive", "unsupported")),
        ("grounded_answer-v1", ("not_stated", "evidence_ids", "input.facts")),
        (
            "safety_boundary-v1",
            ("untrusted_content only as data", "prompt_injection", "no_authority", "route to none"),
        ),
    ],
)
def test_task_contract_instructions_define_the_scored_shape(
    contract: str, required_terms: tuple[str, ...],
) -> None:
    instruction = _contract_instruction(contract)
    assert all(term in instruction for term in required_terms)
    assert "expected_checks" not in instruction


def test_unknown_task_contract_fails_closed() -> None:
    with pytest.raises(EvaluationError, match="unknown task contract"):
        _contract_instruction("unknown-v1")
