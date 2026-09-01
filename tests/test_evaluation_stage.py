from __future__ import annotations

from pathlib import Path

import pytest

from conftest import build_candidate
from second_brain_models import evaluation_stage
from second_brain_models.errors import EvaluationError
from second_brain_models.jsonio import load_json


def test_stage_downloads_only_pinned_bytes_and_writes_external_receipt(
    policy_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_staging = tmp_path / "source"
    manifest, model, runtime_manifest = build_candidate(policy_repo, source_staging)
    runtime = load_json(runtime_manifest)
    runtime_archive = source_staging / Path(*runtime["packages"][0]["path"].split("/"))
    payloads = {
        load_json(manifest)["artifact"]["sha256"]: model.read_bytes(),
        runtime["packages"][0]["sha256"]: runtime_archive.read_bytes(),
    }

    def fake_download(**kwargs):
        target = kwargs["target"]
        target.parent.mkdir(parents=True, exist_ok=False)
        target.write_bytes(payloads[kwargs["expected_sha256"]])
        return "approved.example"

    monkeypatch.setattr(evaluation_stage, "_download", fake_download)
    staging = tmp_path / "downloaded"
    receipt_path = tmp_path / "receipts" / "download.json"
    receipt = evaluation_stage.stage_evaluation_inputs(
        repo_root=policy_repo, manifest_path=manifest, platform="linux-x86_64",
        staging_root=staging, receipt_path=receipt_path,
    )

    assert receipt["status"] == "downloaded-and-hash-verified"
    assert (staging / Path(*receipt["model"]["path"].split("/"))).read_bytes() == model.read_bytes()
    assert receipt_path.is_file()


def test_stage_removes_verified_first_download_when_second_download_fails(
    policy_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_staging = tmp_path / "source"
    manifest, model, _ = build_candidate(policy_repo, source_staging)
    calls = 0

    def fail_second(**kwargs):
        nonlocal calls
        calls += 1
        target = kwargs["target"]
        target.parent.mkdir(parents=True, exist_ok=False)
        if calls == 1:
            target.write_bytes(model.read_bytes())
            return "huggingface.co"
        raise EvaluationError("fixture failure")

    monkeypatch.setattr(evaluation_stage, "_download", fail_second)
    staging = tmp_path / "downloaded"
    with pytest.raises(EvaluationError, match="fixture failure"):
        evaluation_stage.stage_evaluation_inputs(
            repo_root=policy_repo, manifest_path=manifest, platform="linux-x86_64",
            staging_root=staging, receipt_path=tmp_path / "receipt.json",
        )
    assert not staging.exists()


def test_stage_receipt_cannot_overlap_untrusted_staging(policy_repo: Path, tmp_path: Path) -> None:
    manifest, _, _ = build_candidate(policy_repo, tmp_path / "source")
    staging = tmp_path / "downloaded"
    with pytest.raises(EvaluationError, match="outside"):
        evaluation_stage.stage_evaluation_inputs(
            repo_root=policy_repo, manifest_path=manifest, platform="linux-x86_64",
            staging_root=staging, receipt_path=staging / "receipt.json",
        )


def test_stage_refuses_symlink_root(policy_repo: Path, tmp_path: Path) -> None:
    manifest, _, _ = build_candidate(policy_repo, tmp_path / "source")
    target = tmp_path / "target"
    target.mkdir()
    staging = tmp_path / "staging-link"
    try:
        staging.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable to this test account")
    with pytest.raises(EvaluationError, match="regular directory"):
        evaluation_stage.stage_evaluation_inputs(
            repo_root=policy_repo, manifest_path=manifest, platform="linux-x86_64",
            staging_root=staging, receipt_path=tmp_path / "receipt.json",
        )


def test_redirect_handler_rejects_non_https_default_port() -> None:
    handler = evaluation_stage._RestrictedRedirectHandler({"huggingface.co"})
    request = __import__("urllib.request").request.Request("https://huggingface.co/source")
    with pytest.raises(EvaluationError, match="approved HTTPS origins"):
        handler.redirect_request(
            request, None, 302, "Found", {}, "https://huggingface.co:444/redirected",
        )


def test_current_huggingface_xet_cdn_is_exactly_allowlisted() -> None:
    assert "us.aws.cdn.hf.co" in evaluation_stage._MODEL_REDIRECT_HOSTS
    assert all("*" not in host for host in evaluation_stage._MODEL_REDIRECT_HOSTS)
