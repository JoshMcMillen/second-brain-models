from __future__ import annotations

from pathlib import Path

from second_brain_models.candidate import check_candidate
from second_brain_models.canary import build_canary_artifact_bytes
from second_brain_models.jsonio import load_json
from second_brain_models.lifecycle import build_catalog
from second_brain_models.repository import check_repository


REPO_ROOT = Path(__file__).resolve().parents[1]
CANARY_DIR = REPO_ROOT / "fixtures" / "test-channel" / "second-brain-install-canary"
CANARY_MANIFEST = CANARY_DIR / "manifest.json"


def test_canary_bytes_are_reproducible_from_source() -> None:
    """The committed manifest's digest/size must match a fresh rebuild from source.

    The actual few-hundred-byte artifact is never committed (like a real
    model's weights); only its manifest and result are. Anyone must be able
    to reconstruct byte-identical content from this repository's own source.
    """
    manifest = load_json(CANARY_MANIFEST)
    raw = build_canary_artifact_bytes()
    import hashlib

    assert manifest["artifact"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert manifest["artifact"]["size_bytes"] == len(raw)
    assert 0 < len(raw) < 2000


def test_canary_candidate_check_passes_like_any_manifest(tmp_path: Path) -> None:
    manifest = load_json(CANARY_MANIFEST)
    digest = manifest["artifact"]["sha256"]
    staging = tmp_path / "canary-staging"
    artifact_path = staging / "models" / "sha256" / digest / "model.gguf"
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_bytes(build_canary_artifact_bytes())

    report = check_candidate(CANARY_MANIFEST, staging, REPO_ROOT)
    assert report["model_id"] == "second-brain-install-canary"
    assert report["executes_upstream_code"] is False
    assert all(status == "pass" for status in report["checks"].values())


def test_repo_check_validates_the_committed_test_channel_fixture() -> None:
    receipt = check_repository(REPO_ROOT)
    assert receipt["validated"]["test_channel_manifest"] == 1


def test_build_catalog_test_channel_is_installable_and_isolated_from_models(
    tmp_path: Path,
) -> None:
    catalog = build_catalog(
        repo_root=REPO_ROOT, output_path=tmp_path / "test.json", channel="test",
        catalog_version=1, key_id="sha256:" + "a" * 64,
    )
    assert catalog["channel"] == "test"
    assert len(catalog["entries"]) == 1
    entry = catalog["entries"][0]
    assert entry["availability"] == "installable"
    assert entry["manifest"]["model_id"] == "second-brain-install-canary"
    assert entry["manifest_path"] == "fixtures/test-channel/second-brain-install-canary/manifest.json"
    assert entry["manifest"]["promotion"]["channel"] == "test"

    # The real, non-fixture beta/stable channels must never surface it.
    for channel in ("beta", "stable"):
        other = build_catalog(
            repo_root=REPO_ROOT, output_path=tmp_path / f"{channel}.json", channel=channel,
            catalog_version=1, key_id="sha256:" + "a" * 64,
        )
        assert all(item["manifest"]["model_id"] != "second-brain-install-canary" for item in other["entries"])
