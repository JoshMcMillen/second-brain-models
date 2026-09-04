"""The first real catalog publication path: sign, upload, verify, and release.

``docs/publishing-interface-v1.md`` describes the artifact-first receipt a
protected workflow must produce before ``publish.yml`` may stop failing
closed. This module is that implementation for the ``github-release`` host
(see ``second_brain_models.hosting``): a catalog is built and every asset URL
it will ever reference is computed *before* anything is signed, so nothing
about the catalog needs to change after signing. Only then are assets
uploaded to a draft GitHub Release, re-downloaded and verified byte-for-byte,
and only after every verification succeeds is the release attached its
catalog/signature/public key and moved out of draft.

Any verification failure deletes the draft release and raises, so a failed
publish never leaves a half-published release for a client to stumble on.

Network I/O is confined to one small ``ReleaseTransport`` interface so this
whole flow is unit-testable with an in-memory fake (see ``tests/``); the real
``GhCliReleaseTransport`` shells out to the ``gh`` CLI, which is what
``publish.yml`` runs under the protected ``model-publish`` environment.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Protocol

from .errors import ModelCatalogError
from .hosting import asset_filename, release_name, resolve_asset_url
from .jsonio import write_canonical
from .lifecycle import build_catalog
from .schema import validate_value
from .signing import sign_document, verify_document


@dataclass(frozen=True)
class ReleaseAsset:
    """One repository-relative, content-verified object slated for upload.

    ``repo_path`` is the object's permanent content-addressed identity (used
    for naming and URLs); ``source_path`` is where its bytes actually live
    right now, which is *not* always inside this Git checkout. Model and
    runtime-package bytes are never committed to Git (see
    ``second_brain_models.repository.check_repository``), so those come from
    a caller-supplied staging root; a manifest-adjacent license and a
    committed evaluation result come from the repository itself.
    """

    repo_path: str
    source_path: Path
    sha256: str
    size_bytes: int

    @property
    def filename(self) -> str:
        return asset_filename(self.repo_path)


class ReleaseTransport(Protocol):
    """The only network seam this module uses; fakeable for tests."""

    def create_draft_release(self, *, repository: str, release: str) -> None: ...

    def upload_asset(self, *, repository: str, release: str, filename: str, data: bytes) -> None: ...

    def download_asset(self, *, repository: str, release: str, filename: str) -> bytes: ...

    def publish_release(self, *, repository: str, release: str) -> None: ...

    def delete_release(self, *, repository: str, release: str) -> None: ...


class GhCliReleaseTransport:
    """Real transport used in CI: shells out to the authenticated ``gh`` CLI."""

    def __init__(self, *, gh_executable: str = "gh") -> None:
        self._gh = gh_executable

    def _run(self, args: list[str]) -> str:
        result = subprocess.run(
            [self._gh, *args], capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            raise ModelCatalogError(
                f"gh {' '.join(args)} failed with exit {result.returncode}: {result.stderr.strip()}"
            )
        return result.stdout

    def create_draft_release(self, *, repository: str, release: str) -> None:
        self._run([
            "release", "create", release, "--repo", repository, "--draft",
            "--title", release,
            "--notes", f"Assembled by sb-models publish for {release}. Verified before publication.",
        ])

    def upload_asset(self, *, repository: str, release: str, filename: str, data: bytes) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staged = Path(tmp) / filename
            staged.write_bytes(data)
            self._run(["release", "upload", release, str(staged), "--repo", repository, "--clobber"])

    def download_asset(self, *, repository: str, release: str, filename: str) -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            self._run([
                "release", "download", release, "--repo", repository,
                "--pattern", filename, "--dir", tmp, "--clobber",
            ])
            downloaded = Path(tmp) / filename
            try:
                return downloaded.read_bytes()
            except OSError as exc:
                raise ModelCatalogError(
                    f"gh release download did not produce the expected asset {filename!r}"
                ) from exc

    def publish_release(self, *, repository: str, release: str) -> None:
        self._run(["release", "edit", release, "--repo", repository, "--draft=false"])

    def delete_release(self, *, repository: str, release: str) -> None:
        self._run(["release", "delete", release, "--repo", repository, "--yes", "--cleanup-tag"])


def _asset(
    *, base: Path, source_relative: str, identity_path: str | None = None,
    expected_sha256: str | None = None, expected_size: int | None = None,
) -> ReleaseAsset:
    """Read and content-verify one object.

    ``source_relative`` is where the bytes actually live, relative to
    ``base``. ``identity_path`` is the object's permanent content-addressed
    identity used for the asset's flattened filename and its final URL; it
    defaults to ``source_relative`` when the two coincide (results, and
    anything already staged at its content-addressed path).
    """
    identity = identity_path if identity_path is not None else source_relative
    source = base / source_relative
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise ModelCatalogError(
            f"referenced release object is missing: {source_relative} (looked under {base})"
        ) from exc
    digest = hashlib.sha256(raw).hexdigest()
    size = len(raw)
    if expected_sha256 is not None and digest != expected_sha256:
        raise ModelCatalogError(f"local bytes for {source_relative} do not match the signed catalog digest")
    if expected_size is not None and size != expected_size:
        raise ModelCatalogError(f"local bytes for {source_relative} do not match the signed catalog size")
    return ReleaseAsset(repo_path=identity, source_path=source, sha256=digest, size_bytes=size)


@dataclass(frozen=True)
class ReleasePlan:
    release: str
    catalog: dict[str, Any]
    objects: tuple[ReleaseAsset, ...]


def plan_release(
    *, repo_root: Path | str, staging_root: Path | str, catalog: dict[str, Any], host: str,
    repository: str, channel: str, catalog_version: int,
) -> ReleasePlan:
    """Compute every asset's final URL and inject it into a copy of the catalog.

    This never touches the network: URLs are a pure function of the host,
    repository, release name, and each object's own repository-relative
    path. The returned catalog is what gets signed; nothing about it changes
    afterward.

    Model and runtime-package bytes are read from ``staging_root`` (never
    from the Git checkout -- see ``ReleaseAsset``); the manifest-adjacent
    license, the runtime's own license, and the committed evaluation result
    are read from ``repo_root``.
    """
    root = Path(repo_root).resolve()
    staging = Path(staging_root).resolve()
    release = release_name(channel, catalog_version)
    registry: dict[str, ReleaseAsset] = {}
    new_entries: list[dict[str, Any]] = []
    for entry in catalog["entries"]:
        manifest = entry["manifest"]
        runtime_manifest = entry["runtime_manifest"]
        artifact_asset = _asset(
            base=staging, source_relative=manifest["artifact"]["path"],
            expected_sha256=manifest["artifact"]["sha256"], expected_size=manifest["artifact"]["size_bytes"],
        )
        license_asset = _asset(
            base=root, source_relative=manifest["license"]["repository_path"],
            identity_path=manifest["license"]["path"],
            expected_sha256=manifest["license"]["sha256"], expected_size=manifest["license"]["size_bytes"],
        )
        runtime_license_asset = _asset(
            base=root, source_relative=runtime_manifest["license"]["repository_path"],
            identity_path=runtime_manifest["license"]["path"],
            expected_sha256=runtime_manifest["license"]["sha256"],
            expected_size=runtime_manifest["license"]["size_bytes"],
        )
        result_asset = _asset(
            base=root, source_relative=entry["result_path"], expected_sha256=entry["result_sha256"],
        )
        package_assets = {
            package["platform"]: _asset(
                base=staging, source_relative=package["path"],
                expected_sha256=package["sha256"], expected_size=package["size_bytes"],
            )
            for package in runtime_manifest["packages"]
        }
        for asset in (artifact_asset, license_asset, runtime_license_asset, result_asset, *package_assets.values()):
            registry.setdefault(asset.repo_path, asset)

        entry_with_assets = dict(entry)
        entry_with_assets["assets"] = {
            "artifact_url": resolve_asset_url(
                host=host, repository=repository, release=release, repository_relative_path=artifact_asset.repo_path,
            ),
            "license_url": resolve_asset_url(
                host=host, repository=repository, release=release, repository_relative_path=license_asset.repo_path,
            ),
            "runtime_license_url": resolve_asset_url(
                host=host, repository=repository, release=release,
                repository_relative_path=runtime_license_asset.repo_path,
            ),
            "result_url": resolve_asset_url(
                host=host, repository=repository, release=release, repository_relative_path=result_asset.repo_path,
            ),
            "runtime_package_urls": {
                platform: resolve_asset_url(
                    host=host, repository=repository, release=release, repository_relative_path=asset.repo_path,
                )
                for platform, asset in package_assets.items()
            },
        }
        new_entries.append(entry_with_assets)

    new_catalog = dict(catalog)
    new_catalog["entries"] = new_entries
    new_catalog["distribution"] = {"host": host, "release": release}
    return ReleasePlan(
        release=release, catalog=new_catalog,
        objects=tuple(sorted(registry.values(), key=lambda item: item.repo_path)),
    )


def publish_release(
    *, repo_root: Path | str, staging_root: Path | str, channel: str, catalog_version: int,
    private_key: Any, public_key: Any, public_key_path: Path | str,
    repository: str, host: str, transport: ReleaseTransport,
    catalog_output_path: Path | str, signature_output_path: Path | str,
    expires_days: int = 7, receipt_path: Path | str | None = None,
) -> dict[str, Any]:
    """Build, sign, upload, verify, and publish one catalog release.

    On any verification failure the draft release is deleted and a
    ``ModelCatalogError`` is raised; the prior signed catalog remains the
    latest published state (this function never rewrites Git history or an
    already-published release).
    """
    from .signing import public_key_id

    root = Path(repo_root).resolve()
    key_id = public_key_id(public_key)

    with tempfile.TemporaryDirectory() as tmp_name:
        tmp = Path(tmp_name)
        unsigned_path = tmp / "unsigned-catalog.json"
        catalog = build_catalog(
            repo_root=root, output_path=unsigned_path, channel=channel,
            catalog_version=catalog_version, key_id=key_id, expires_days=expires_days,
        )
        plan = plan_release(
            repo_root=root, staging_root=staging_root, catalog=catalog, host=host, repository=repository,
            channel=channel, catalog_version=catalog_version,
        )
        validate_value(plan.catalog, "catalog", root)

        catalog_path = Path(catalog_output_path)
        signature_path = Path(signature_output_path)
        write_canonical(catalog_path, plan.catalog)
        sign_document(catalog_path, signature_path, private_key=private_key)
        # Fail fast locally, before any network call, if signing somehow
        # produced a document/signature pair that does not verify.
        verify_document(catalog_path, signature_path, public_key=public_key)

        transport.create_draft_release(repository=repository, release=plan.release)
        uploaded: list[dict[str, Any]] = []
        try:
            for asset in plan.objects:
                data = asset.source_path.read_bytes()
                transport.upload_asset(
                    repository=repository, release=plan.release, filename=asset.filename, data=data,
                )
            for asset in plan.objects:
                downloaded = transport.download_asset(
                    repository=repository, release=plan.release, filename=asset.filename,
                )
                digest = hashlib.sha256(downloaded).hexdigest()
                verified = digest == asset.sha256 and len(downloaded) == asset.size_bytes
                uploaded.append({
                    "repo_path": asset.repo_path,
                    "asset_filename": asset.filename,
                    "url": resolve_asset_url(
                        host=host, repository=repository, release=plan.release,
                        repository_relative_path=asset.repo_path,
                    ),
                    "sha256": asset.sha256,
                    "size_bytes": asset.size_bytes,
                    "verified": verified,
                })
                if not verified:
                    raise ModelCatalogError(
                        f"re-download verification failed for {asset.repo_path} "
                        f"(expected sha256={asset.sha256} size={asset.size_bytes}, "
                        f"got sha256={digest} size={len(downloaded)})"
                    )

            catalog_bytes = catalog_path.read_bytes()
            signature_bytes = signature_path.read_bytes()
            public_key_bytes = Path(public_key_path).read_bytes()
            catalog_filename = f"{channel}.json"
            signature_filename = f"{channel}.json.sig"
            public_key_filename = "catalog-release-v1.pem"
            transport.upload_asset(
                repository=repository, release=plan.release, filename=catalog_filename, data=catalog_bytes,
            )
            transport.upload_asset(
                repository=repository, release=plan.release, filename=signature_filename, data=signature_bytes,
            )
            transport.upload_asset(
                repository=repository, release=plan.release, filename=public_key_filename, data=public_key_bytes,
            )
            for filename, expected in (
                (catalog_filename, catalog_bytes),
                (signature_filename, signature_bytes),
                (public_key_filename, public_key_bytes),
            ):
                downloaded = transport.download_asset(
                    repository=repository, release=plan.release, filename=filename,
                )
                if downloaded != expected:
                    raise ModelCatalogError(f"re-download verification failed for {filename}")

            transport.publish_release(repository=repository, release=plan.release)
        except Exception:
            transport.delete_release(repository=repository, release=plan.release)
            raise

        receipt: dict[str, Any] = {
            "schema_version": 1,
            "channel": channel,
            "catalog_version": catalog_version,
            "release": plan.release,
            "host": host,
            "repository": repository,
            "key_id": key_id,
            "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(),
            "objects": uploaded,
        }
        if receipt_path is not None:
            write_canonical(receipt_path, receipt)
        return receipt
