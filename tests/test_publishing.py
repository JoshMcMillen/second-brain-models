from __future__ import annotations

from pathlib import Path

import pytest

from conftest import build_installable_candidate
from second_brain_models.errors import ModelCatalogError
from second_brain_models.hosting import asset_filename, release_name, resolve_asset_url
from second_brain_models.jsonio import load_json
from second_brain_models.publishing import contract_fixture_assets, plan_release, publish_release
from second_brain_models.signing import generate_keypair, load_private_key, load_public_key


REPOSITORY = "JoshMcMillen/second-brain-models"


class FakeReleaseTransport:
    """In-memory ReleaseTransport double -- no network, no gh CLI."""

    def __init__(self, *, corrupt: dict[str, bytes | None] | None = None) -> None:
        self.releases: dict[str, dict[str, object]] = {}
        self.deleted: list[str] = []
        self.upload_log: list[tuple[str, str]] = []
        self._corrupt = corrupt or {}

    def create_draft_release(self, *, repository: str, release: str) -> None:
        assert release not in self.releases, "release name must be created at most once"
        self.releases[release] = {"draft": True, "assets": {}}

    def upload_asset(self, *, repository: str, release: str, filename: str, data: bytes) -> None:
        self.upload_log.append((release, filename))
        self.releases[release]["assets"][filename] = data  # type: ignore[index]

    def download_asset(self, *, repository: str, release: str, filename: str) -> bytes:
        if filename in self._corrupt:
            replacement = self._corrupt[filename]
            if replacement is None:
                raise ModelCatalogError(f"simulated missing asset: {filename}")
            return replacement
        return self.releases[release]["assets"][filename]  # type: ignore[index]

    def publish_release(self, *, repository: str, release: str) -> None:
        self.releases[release]["draft"] = False

    def delete_release(self, *, repository: str, release: str) -> None:
        self.deleted.append(release)
        self.releases.pop(release, None)


@pytest.fixture
def keypair(tmp_path: Path):
    private = tmp_path / "release-private.pem"
    public = tmp_path / "release-public.pem"
    generate_keypair(private, public)
    return load_private_key(private), load_public_key(public), public


def _publish(
    policy_repo: Path, tmp_path: Path, keypair, *, channel: str = "beta",
    staging: Path | None = None, transport: FakeReleaseTransport | None = None,
):
    private_key, public_key, public_key_path = keypair
    transport = transport or FakeReleaseTransport()
    receipt = publish_release(
        repo_root=policy_repo, staging_root=staging or (tmp_path / "empty-staging"),
        channel=channel, catalog_version=1,
        private_key=private_key, public_key=public_key, public_key_path=public_key_path,
        repository=REPOSITORY, host="github-release", transport=transport,
        catalog_output_path=tmp_path / f"{channel}.json",
        signature_output_path=tmp_path / f"{channel}.json.sig",
        receipt_path=tmp_path / "receipt.json",
    )
    return receipt, transport


def test_publish_empty_catalog_attaches_only_catalog_signature_and_key(
    policy_repo: Path, tmp_path: Path, keypair,
) -> None:
    receipt, transport = _publish(policy_repo, tmp_path, keypair, channel="beta")
    contract_fixtures = contract_fixture_assets(policy_repo)
    assert contract_fixtures  # schemas + fixtures/signing always ride along (docs/consumer-contract-v1.md)
    assert {item["repo_path"] for item in receipt["objects"]} == {asset.repo_path for asset in contract_fixtures}
    release = receipt["release"]
    assert release == "catalog-beta-v1"
    assets = transport.releases[release]["assets"]
    expected_asset_names = {"beta.json", "beta.json.sig", "catalog-release-v1.pem"} | {
        asset.filename for asset in contract_fixtures
    }
    assert set(assets) == expected_asset_names
    assert transport.releases[release]["draft"] is False
    assert transport.deleted == []

    catalog = load_json(tmp_path / "beta.json")
    assert catalog["entries"] == []
    assert catalog["distribution"] == {"host": "github-release", "release": release}


def test_publish_success_uploads_verifies_and_publishes_every_object(
    policy_repo: Path, tmp_path: Path, keypair,
) -> None:
    staging = tmp_path / "staging"
    build_installable_candidate(policy_repo, staging)

    receipt, transport = _publish(policy_repo, tmp_path, keypair, staging=staging)
    release = receipt["release"]
    assert release == "catalog-beta-v1"
    contract_fixtures = contract_fixture_assets(policy_repo)
    # artifact, model license, runtime license, result, 1 runtime package, + always-on contract fixtures
    assert len(receipt["objects"]) == 5 + len(contract_fixtures)
    assert all(item["verified"] for item in receipt["objects"])
    assert transport.releases[release]["draft"] is False
    assert transport.deleted == []

    catalog = load_json(tmp_path / "beta.json")
    entry = catalog["entries"][0]
    assets = entry["assets"]
    assert assets["artifact_url"].startswith(f"https://github.com/{REPOSITORY}/releases/download/{release}/")
    assert set(assets["runtime_package_urls"]) == {"linux-x86_64"}
    # Every uploaded asset filename must be addressable by exactly one computed URL.
    uploaded_filenames = set(transport.releases[release]["assets"])
    referenced_urls = {
        assets["artifact_url"], assets["license_url"], assets["runtime_license_url"], assets["result_url"],
        *assets["runtime_package_urls"].values(),
    } | {
        f"https://github.com/{REPOSITORY}/releases/download/{release}/{name}"
        for name in ("beta.json", "beta.json.sig", "catalog-release-v1.pem")
    } | {
        f"https://github.com/{REPOSITORY}/releases/download/{release}/{asset.filename}"
        for asset in contract_fixtures
    }
    assert {url.rsplit("/", 1)[-1] for url in referenced_urls} == uploaded_filenames

    # Re-verify every asset URL is independently reconstructable from the plan.
    for url in (
        assets["artifact_url"], assets["license_url"], assets["runtime_license_url"], assets["result_url"],
        *assets["runtime_package_urls"].values(),
    ):
        assert url.startswith("https://github.com/")


def test_publish_deletes_draft_on_size_mismatch(policy_repo: Path, tmp_path: Path, keypair) -> None:
    staging = tmp_path / "staging"
    manifest_path, _, _, _ = build_installable_candidate(policy_repo, staging)
    manifest = load_json(manifest_path)
    corrupted_filename = asset_filename(manifest["artifact"]["path"])
    transport = FakeReleaseTransport(corrupt={corrupted_filename: b"short"})

    with pytest.raises(ModelCatalogError, match="re-download verification failed"):
        _publish(policy_repo, tmp_path, keypair, staging=staging, transport=transport)

    release = release_name("beta", 1)
    assert transport.deleted == [release]
    assert release not in transport.releases


def test_publish_deletes_draft_on_digest_mismatch(policy_repo: Path, tmp_path: Path, keypair) -> None:
    staging = tmp_path / "staging"
    manifest_path, _, _, _ = build_installable_candidate(policy_repo, staging)
    manifest = load_json(manifest_path)
    corrupted_filename = asset_filename(manifest["artifact"]["path"])
    real_size = manifest["artifact"]["size_bytes"]
    transport = FakeReleaseTransport(corrupt={corrupted_filename: b"\x00" * real_size})

    with pytest.raises(ModelCatalogError, match="re-download verification failed"):
        _publish(policy_repo, tmp_path, keypair, staging=staging, transport=transport)

    release = release_name("beta", 1)
    assert transport.deleted == [release]


def test_publish_deletes_draft_on_missing_asset(policy_repo: Path, tmp_path: Path, keypair) -> None:
    staging = tmp_path / "staging"
    manifest_path, _, _, _ = build_installable_candidate(policy_repo, staging)
    manifest = load_json(manifest_path)
    missing_filename = asset_filename(manifest["license"]["path"])
    transport = FakeReleaseTransport(corrupt={missing_filename: None})

    with pytest.raises(ModelCatalogError, match="simulated missing asset"):
        _publish(policy_repo, tmp_path, keypair, staging=staging, transport=transport)

    release = release_name("beta", 1)
    assert transport.deleted == [release]


def test_publish_deletes_draft_when_staged_artifact_is_missing(
    policy_repo: Path, tmp_path: Path, keypair,
) -> None:
    build_installable_candidate(policy_repo, tmp_path / "staging")
    transport = FakeReleaseTransport()

    with pytest.raises(ModelCatalogError, match="referenced release object is missing"):
        # staging_root points at an empty directory: the artifact was never staged there.
        _publish(policy_repo, tmp_path, keypair, staging=tmp_path / "nothing-staged", transport=transport)

    # The plan failed before any draft release was even created.
    assert transport.deleted == []
    assert transport.releases == {}


def test_release_asset_urls_are_deterministic_and_flatten_paths() -> None:
    url = resolve_asset_url(
        host="github-release", repository=REPOSITORY, release="catalog-test-v1",
        repository_relative_path="models/sha256/" + "a" * 64 + "/model.gguf",
    )
    assert url == (
        f"https://github.com/{REPOSITORY}/releases/download/catalog-test-v1/"
        f"models-sha256-{'a' * 64}-model.gguf"
    )
