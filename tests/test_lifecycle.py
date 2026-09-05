from __future__ import annotations

from pathlib import Path

import pytest

from conftest import build_candidate
from second_brain_models.errors import DocumentError, PolicyError
from second_brain_models.jsonio import load_json, write_canonical
from second_brain_models.lifecycle import build_catalog
from second_brain_models.schema import validate_value


def test_quarantined_candidate_does_not_block_stable_catalog_build(policy_repo: Path, tmp_path: Path) -> None:
    build_candidate(policy_repo, tmp_path / "external-staging")
    catalog = build_catalog(
        repo_root=policy_repo, output_path=tmp_path / "stable.json", channel="stable",
        catalog_version=1, key_id="sha256:" + "a" * 64,
    )
    assert catalog["entries"] == []
    assert catalog["channel"] == "stable"


def test_catalog_version_must_increase_existing_channel(policy_repo: Path, tmp_path: Path) -> None:
    catalog_path = policy_repo / "catalog" / "stable.json"
    build_catalog(
        repo_root=policy_repo, output_path=catalog_path, channel="stable",
        catalog_version=3, key_id="sha256:" + "a" * 64,
    )
    with pytest.raises(PolicyError, match="greater"):
        build_catalog(
            repo_root=policy_repo, output_path=tmp_path / "replacement.json", channel="stable",
            catalog_version=3, key_id="sha256:" + "a" * 64,
        )


def test_stable_promotion_requires_installable_beta_history(policy_repo: Path, tmp_path: Path) -> None:
    manifest_path, _, _ = build_candidate(policy_repo, tmp_path / "external-staging")
    manifest = load_json(manifest_path)
    manifest["promotion"] = {
        "policy_id": "promotion-v1", "channel": "stable", "status": "approved",
        "human_review_required": True, "approved_task_contracts": ["intent_routing-v1"],
        "review_reference": "owner-stable-review-1",
    }
    write_canonical(manifest_path, manifest)
    with pytest.raises(PolicyError, match="catalog/beta.json"):
        build_catalog(
            repo_root=policy_repo, output_path=tmp_path / "stable.json", channel="stable",
            catalog_version=1, key_id="sha256:" + "a" * 64,
        )


def test_installable_promotion_requires_an_approved_task_contract(
    policy_repo: Path, tmp_path: Path,
) -> None:
    manifest_path, _, _ = build_candidate(policy_repo, tmp_path / "external-staging")
    manifest = load_json(manifest_path)
    manifest["promotion"] = {
        "policy_id": "promotion-v1", "channel": "beta", "status": "approved",
        "human_review_required": True, "approved_task_contracts": [],
        "review_reference": "owner-beta-review-1",
    }
    write_canonical(manifest_path, manifest)
    with pytest.raises(DocumentError, match="manifest schema validation"):
        build_catalog(
            repo_root=policy_repo, output_path=tmp_path / "beta.json", channel="beta",
            catalog_version=1, key_id="sha256:" + "a" * 64,
        )


def test_test_channel_promotion_can_grant_no_task_contracts(
    policy_repo: Path, tmp_path: Path,
) -> None:
    manifest_path, _, _ = build_candidate(policy_repo, tmp_path / "external-staging")
    manifest = load_json(manifest_path)
    manifest["promotion"] = {
        "policy_id": "promotion-v1", "channel": "test", "status": "approved",
        "human_review_required": True, "approved_task_contracts": [],
        "review_reference": "owner-test-review-1",
    }

    validate_value(manifest, "manifest", policy_repo)


def test_test_channel_promotion_rejects_task_contracts(
    policy_repo: Path, tmp_path: Path,
) -> None:
    manifest_path, _, _ = build_candidate(policy_repo, tmp_path / "external-staging")
    manifest = load_json(manifest_path)
    manifest["promotion"] = {
        "policy_id": "promotion-v1", "channel": "test", "status": "approved",
        "human_review_required": True, "approved_task_contracts": ["intent_routing-v1"],
        "review_reference": "owner-test-review-1",
    }

    with pytest.raises(DocumentError, match="manifest schema validation"):
        validate_value(manifest, "manifest", policy_repo)


def test_test_catalog_requires_the_dedicated_canary_fixture(
    policy_repo: Path, tmp_path: Path,
) -> None:
    with pytest.raises(PolicyError, match="exactly fixtures/test-channel/second-brain-install-canary/manifest.json"):
        build_catalog(
            repo_root=policy_repo, output_path=tmp_path / "test.json", channel="test",
            catalog_version=1, key_id="sha256:" + "a" * 64,
        )
