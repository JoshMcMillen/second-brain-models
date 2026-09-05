"""Human-gated catalog assembly and signed revocation record creation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Any

from .errors import DocumentError, PolicyError
from .jsonio import load_json, write_canonical
from .policy import load_policy_bundle
from .schema import validate_file, validate_value
from .runtime import validate_model_runtime_reference
from .evaluation import validate_result_consistency
from .license import validate_license_binding


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_revocation(
    *, repo_root: Path | str, manifest_path: Path | str, reason_code: str,
    advisory: str, review_reference: str, output_path: Path | str,
    replacement_sha256: str | None = None,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    policies = load_policy_bundle(root)
    manifest_source = Path(manifest_path).resolve()
    manifest = validate_file(manifest_source, "manifest", root)
    validate_license_binding(manifest_source, manifest["license"], root)
    if reason_code not in policies["promotion"]["revocation"]["reasons"]:
        raise PolicyError(f"reason_code {reason_code!r} is not allowed by promotion-v1")
    result_source = root / manifest["evaluation"]["result_path"]
    result = validate_file(result_source, "result", root)
    manifest_digest = _hash(manifest_source)
    result_digest = _hash(result_source)
    if result["subject"]["manifest_sha256"] != manifest_digest:
        raise DocumentError("result does not bind the exact manifest being revoked")
    artifact_digest = manifest["artifact"]["sha256"]
    record = {
        "schema_version": 1,
        "revocation_id": f"revocation-{artifact_digest}",
        "model_id": manifest["model_id"],
        "release": manifest["release"],
        "artifact_sha256": artifact_digest,
        "manifest_sha256": manifest_digest,
        "result_sha256": result_digest,
        "reason_code": reason_code,
        "advisory": advisory,
        "revoked_at": _timestamp(_now()),
        "replacement_sha256": replacement_sha256,
        "review_reference": review_reference,
    }
    validate_value(record, "revocation", root)
    write_canonical(output_path, record)
    return record


def build_catalog(
    *, repo_root: Path | str, output_path: Path | str, channel: str,
    catalog_version: int, key_id: str, expires_days: int = 7,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    load_policy_bundle(root)
    if channel not in {"beta", "stable", "revoked", "test"}:
        raise PolicyError("catalog channel must be beta, stable, revoked, or test")
    if catalog_version < 1 or expires_days < 1 or expires_days > 30:
        raise PolicyError("catalog_version and expiration must be bounded positive values")
    current_catalog_path = root / "catalog" / f"{channel}.json"
    if current_catalog_path.is_file():
        current = validate_file(current_catalog_path, "catalog", root)
        if current["channel"] != channel or catalog_version <= current["catalog_version"]:
            raise PolicyError("catalog_version must be greater than the existing channel catalog version")
    beta_history: dict[str, Any] | None = None
    if channel == "stable":
        beta_history_path = root / "catalog" / "beta.json"
        if beta_history_path.is_file():
            beta_history = validate_file(beta_history_path, "catalog", root)
            if beta_history["channel"] != "beta":
                raise PolicyError("stable promotion history must come from the beta catalog")
    revocations: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "revocations").glob("*.json")) if (root / "revocations").is_dir() else []:
        record = validate_file(path, "revocation", root)
        revocations[record["artifact_sha256"]] = record

    entries: list[dict[str, Any]] = []
    # The dedicated "test" channel serves one small, permanently-fixed,
    # non-model connectivity fixture (see
    # fixtures/test-channel/second-brain-install-canary/) so
    # Second Brain can exercise verify/download/install without a real
    # model. It lives outside models/ and outside the candidate->beta->
    # stable promotion ladder, but is otherwise validated identically.
    manifest_root = root / ("fixtures/test-channel" if channel == "test" else "models")
    manifest_paths = sorted(manifest_root.glob("*/manifest.json")) if manifest_root.is_dir() else []
    if channel == "test":
        expected_path = manifest_root / "second-brain-install-canary" / "manifest.json"
        if manifest_paths != [expected_path]:
            raise PolicyError(
                "test catalog requires exactly "
                "fixtures/test-channel/second-brain-install-canary/manifest.json"
            )
    for manifest_path in manifest_paths:
        manifest = validate_file(manifest_path, "manifest", root)
        promotion = manifest["promotion"]
        artifact_digest = manifest["artifact"]["sha256"]
        revocation = revocations.get(artifact_digest)
        if channel == "revoked":
            if revocation is None:
                continue
        else:
            if promotion["channel"] != channel or promotion["status"] != "approved" or revocation is not None:
                continue
            if not promotion.get("review_reference"):
                raise PolicyError(f"published manifest lacks review_reference: {manifest_path}")
            if channel == "test" and promotion["approved_task_contracts"]:
                raise PolicyError(f"test manifest grants task contracts: {manifest_path}")
            if channel != "test" and not promotion["approved_task_contracts"]:
                raise PolicyError(f"published manifest approves no task contracts: {manifest_path}")
        if channel == "stable" and (
            beta_history is None
            or not any(
                entry["availability"] == "installable"
                and entry["manifest"]["artifact"]["sha256"] == artifact_digest
                for entry in beta_history["entries"]
            )
        ):
            raise PolicyError("stable promotion requires the exact model artifact to appear as installable in catalog/beta.json")
        validate_license_binding(manifest_path, manifest["license"], root)
        # The test-channel fixture is a permanent, self-attested connectivity
        # canary rather than a promoted model, so it does not require the
        # runtime family itself to have completed the separate, owner-gated
        # runtime approval lifecycle that beta/stable promotion requires.
        exact_runtime = validate_model_runtime_reference(
            manifest, root, require_approved=channel not in ("revoked", "test"),
        )
        if not set(promotion["approved_task_contracts"]) <= set(manifest["evaluation"]["task_contracts"]):
            raise PolicyError(f"manifest grants a task contract that was not evaluated: {manifest_path}")
        result_path = root / manifest["evaluation"]["result_path"]
        if manifest["evaluation"]["result_path"] != f"results/{artifact_digest}/result.json":
            raise DocumentError("result path must be content-addressed by the exact model artifact digest")
        result = validate_file(result_path, "result", root)
        manifest_digest = _hash(manifest_path)
        manifest_relative = manifest_path.relative_to(root).as_posix()
        if (
            result["subject"]["manifest_path"] != manifest_relative
            or result["subject"]["manifest_sha256"] != manifest_digest
            or result["subject"]["manifest"] != manifest
        ):
            raise DocumentError(f"result does not snapshot exact manifest {manifest_path}")
        validate_result_consistency(result, manifest, exact_runtime, root)
        recommendation = result["decision"]["promotion_recommendation"]
        if channel != "revoked" and (recommendation == "hold" or (channel == "stable" and recommendation != "stable")):
            raise PolicyError(f"result does not qualify for {channel}: {result_path}")
        if channel != "revoked" and not set(promotion["approved_task_contracts"]) <= set(
            result["decision"]["eligible_task_contracts"]
        ):
            raise PolicyError(f"manifest grants a task contract that did not meet its tier threshold: {manifest_path}")
        entries.append({
            "manifest_path": manifest_path.relative_to(root).as_posix(),
            "manifest_sha256": manifest_digest,
            "result_path": result_path.relative_to(root).as_posix(),
            "result_sha256": _hash(result_path),
            "runtime_manifest_path": manifest["runtime"]["manifest_path"],
            "runtime_manifest_sha256": manifest["runtime"]["manifest_sha256"],
            "availability": "revoked" if channel == "revoked" else "installable",
            "manifest": manifest,
            "runtime_manifest": exact_runtime,
            "revocation": revocation if channel == "revoked" else None,
        })
    generated = _now()
    catalog: dict[str, Any] = {
        "schema_version": 1,
        "catalog_id": "second-brain-models",
        "channel": channel,
        "generated_at": _timestamp(generated),
        "promotion_policy": "promotion-v1",
        "entries": sorted(entries, key=lambda item: (item["manifest"]["model_id"], item["manifest"]["release"])),
    }
    catalog["catalog_version"] = catalog_version
    catalog["key_id"] = key_id
    catalog["expires_at"] = _timestamp(generated + timedelta(days=expires_days))
    validate_value(catalog, "catalog", root)
    write_canonical(output_path, catalog)
    return catalog
