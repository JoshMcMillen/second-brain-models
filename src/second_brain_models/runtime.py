"""Cross-field validation for immutable, reviewed runtime packages."""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import urllib.parse
from typing import Any

from .errors import DocumentError, PolicyError
from .license import validate_license_binding
from .policy import load_policy_bundle
from .schema import validate_file


def validate_runtime_manifest(path: Path | str, repo_root: Path | str, *, require_approved: bool = False) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    runtime = validate_file(path, "runtime", root)
    validate_license_binding(path, runtime["license"], root)
    policies = load_policy_bundle(root)
    entries = [entry for entry in policies["runtime"]["allowed_runtime_families"] if entry["runtime_id"] == runtime["runtime_id"]]
    if len(entries) != 1:
        raise PolicyError("runtime family is not admitted for candidate review")
    allow = entries[0]
    if allow["decision"] != "candidate_review_only":
        raise PolicyError("runtime family allowlist must grant candidate review only")
    if runtime["upstream"]["repository"] != allow["publisher_repository"]:
        raise PolicyError("runtime upstream repository differs from the allowlist")
    if runtime["api_contract"] != allow["api_contract"]:
        raise PolicyError("runtime API contract differs from the allowlist")
    if require_approved and runtime["human_review"]["status"] != "approved":
        raise PolicyError("runtime release has not received human approval")
    if require_approved:
        source = Path(path).resolve()
        relative = source.relative_to(root).as_posix()
        from .candidate import sha256_file

        digest = sha256_file(source)
        approvals = [item for item in policies["runtime"]["approved_runtime_manifests"] if item["manifest_path"] == relative]
        if len(approvals) != 1:
            raise PolicyError("exact runtime manifest is not listed in approved_runtime_manifests")
        approval = approvals[0]
        expected = {
            "manifest_sha256": digest,
            "runtime_id": runtime["runtime_id"],
            "version": runtime["version"],
            "revision": runtime["upstream"]["revision"],
            "decision": "approved",
        }
        if any(approval[key] != value for key, value in expected.items()):
            raise PolicyError("runtime manifest approval does not match the exact reviewed document")

    package_keys: set[tuple[str, str]] = set()
    package_digests: set[tuple[str, str]] = set()
    for package in runtime["packages"]:
        digest = package["sha256"]
        relative = PurePosixPath(package["path"])
        if relative.parts[:2] != ("runtimes", "sha256") or len(relative.parts) != 4 or relative.parts[2] != digest:
            raise DocumentError("runtime package path must embed its exact SHA-256")
        parsed = urllib.parse.urlsplit(package["url"])
        if parsed.scheme != "https" or parsed.netloc != "models.avnxmcp.org" or parsed.path.lstrip("/") != package["path"] or parsed.query or parsed.fragment:
            raise DocumentError("runtime package URL must be the exact approved origin and content path")
        upstream_url = urllib.parse.urlsplit(package["upstream_url"])
        repository_parts = runtime["upstream"]["repository"].split("/")
        upstream_prefix = "/" + "/".join(repository_parts[1:]) + "/"
        if (
            upstream_url.scheme != "https" or upstream_url.hostname != repository_parts[0]
            or upstream_url.username is not None or upstream_url.query or upstream_url.fragment
            or not upstream_url.path.startswith(upstream_prefix)
        ):
            raise DocumentError("runtime upstream package URL is not on the exact official repository origin")
        if repository_parts[0] == "github.com" and not upstream_url.path.startswith(upstream_prefix + "releases/download/"):
            raise DocumentError("GitHub runtime package must come from the exact repository release path")
        if PurePosixPath(upstream_url.path).name != PurePosixPath(package["path"]).name:
            raise DocumentError("mirrored runtime package filename differs from official upstream package")
        key = (package["platform"], package["path"])
        if key in package_keys:
            raise DocumentError("duplicate runtime platform/package path")
        package_keys.add(key)
        package_digests.add((package["platform"], digest))
    evidence_digests = {(item["platform"], item["package_sha256"]) for item in runtime["no_egress_evidence"]}
    if evidence_digests and not evidence_digests <= package_digests:
        raise PolicyError("runtime no-egress evidence references an unknown platform/package digest")
    if runtime["human_review"]["status"] == "approved" and evidence_digests != package_digests:
        raise PolicyError("every approved runtime package must have one matching no-egress evidence record")
    return runtime


def validate_model_runtime_reference(
    manifest: dict[str, Any], repo_root: Path | str, *, require_approved: bool = False,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    reference = manifest["runtime"]
    runtime_path = (root / reference["manifest_path"]).resolve()
    try:
        runtime_path.relative_to(root)
    except ValueError as exc:
        raise DocumentError("runtime manifest path escapes the repository") from exc
    runtime = validate_runtime_manifest(runtime_path, root, require_approved=require_approved)
    from .candidate import sha256_file

    if sha256_file(runtime_path) != reference["manifest_sha256"]:
        raise DocumentError("model manifest runtime manifest digest mismatch")
    expected = {
        "runtime_id": runtime["runtime_id"],
        "version": runtime["version"],
        "revision": runtime["upstream"]["revision"],
        "api_contract": runtime["api_contract"],
    }
    for key, value in expected.items():
        if reference[key] != value:
            raise DocumentError(f"model runtime reference {key} does not match exact runtime manifest")
    return runtime
