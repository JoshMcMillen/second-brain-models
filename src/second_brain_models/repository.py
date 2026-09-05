"""Whole-repository validation used by every workflow."""
from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from .errors import DocumentError
from .policy import load_policy_bundle
from .schema import validate_file, validate_schema_set


_FORBIDDEN_REPOSITORY_SUFFIXES = {
    ".gguf", ".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".onnx",
    ".zip", ".tar", ".gz", ".tgz", ".zst", ".7z", ".rar", ".whl",
    ".exe", ".dll", ".so", ".dylib", ".msi", ".pkl", ".pickle",
}
_IGNORED_SCAN_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", ".wrangler"}


def _reject_repository_binaries(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file() or any(part in _IGNORED_SCAN_PARTS for part in path.relative_to(root).parts):
            continue
        if path.suffix.casefold() in _FORBIDDEN_REPOSITORY_SUFFIXES:
            raise DocumentError(f"model/runtime/package bytes are forbidden in Git: {path.relative_to(root)}")
        try:
            raw = path.read_bytes()
            head = raw[:4096]
        except OSError as exc:
            raise DocumentError(f"could not inspect repository file {path.relative_to(root)}: {exc}") from exc
        if head.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04", b"\x1f\x8b")) or b"\x00" in head:
            raise DocumentError(f"unknown binary/executable content is forbidden in Git: {path.relative_to(root)}")
        private_header = re.compile(br"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
        github_token = re.compile(br"(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}")
        cloudflare_token = re.compile(br"(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}")
        if private_header.search(raw) or github_token.search(raw) or cloudflare_token.search(raw):
            raise DocumentError(f"private key or token material is forbidden in repository data: {path.relative_to(root)}")


def check_repository(repo_root: Path | str) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    _reject_repository_binaries(root)
    for relative in ("policy", "schemas", "evals", "models", "runtimes", "results", "catalog", "revocations"):
        directory = root / relative
        if directory.is_symlink():
            raise DocumentError(f"repository trust path is a symlink: {relative}")
        if directory.is_dir():
            for path in directory.rglob("*"):
                if path.is_symlink():
                    raise DocumentError(f"symlinks are forbidden in repository trust data: {path.relative_to(root)}")
    validate_schema_set(root)
    load_policy_bundle(root)
    counts = {"manifest": 0, "test_channel_manifest": 0, "runtime": 0, "result": 0, "catalog": 0, "revocation": 0}
    groups = (
        ("result", ("results/*/*.json",)),
        ("catalog", ("catalog/*.json",)),
        ("revocation", ("revocations/*.json",)),
    )
    for kind, patterns in groups:
        paths: set[Path] = set()
        for pattern in patterns:
            paths.update(root.glob(pattern))
        for path in sorted(paths):
            if path.name.endswith(".sig"):
                continue
            validate_file(path, kind, root)
            counts[kind] += 1
    from .runtime import validate_model_runtime_reference, validate_runtime_manifest
    from .license import validate_license_binding

    runtime_paths = sorted(root.glob("runtimes/*/manifest.json"))
    for path in runtime_paths:
        value = validate_runtime_manifest(path, root, require_approved=False)
        expected_directory = f"{value['runtime_id'].removesuffix('-server')}-{value['version']}"
        if path.parent.name != expected_directory:
            raise DocumentError(
                f"runtime manifest directory must equal the exact runtime/version id {expected_directory!r}: {path.relative_to(root)}"
            )
        counts["runtime"] += 1
    model_paths = sorted(root.glob("models/*/manifest.json"))
    for path in model_paths:
        value = validate_file(path, "manifest", root)
        if path.parent.name != value["model_id"]:
            raise DocumentError(f"model manifest directory must equal model_id: {path.relative_to(root)}")
        validate_license_binding(path, value["license"], root)
        validate_model_runtime_reference(value, root, require_approved=False)
        counts["manifest"] += 1
    test_channel_paths = sorted(root.glob("fixtures/test-channel/*/manifest.json"))
    for path in test_channel_paths:
        value = validate_file(path, "manifest", root)
        if path.parent.name != value["model_id"]:
            raise DocumentError(f"test-channel fixture directory must equal model_id: {path.relative_to(root)}")
        if value["promotion"]["channel"] != "test":
            raise DocumentError(f"fixtures/test-channel manifest must declare promotion.channel test: {path.relative_to(root)}")
        validate_license_binding(path, value["license"], root)
        validate_model_runtime_reference(value, root, require_approved=False)
        counts["test_channel_manifest"] += 1
    forbidden_roots = [root / "artifacts", root / "downloads", root / "staging"]
    if any(path.exists() for path in forbidden_roots):
        raise DocumentError("candidate/model bytes must not be stored in the Git repository")
    return {"schema_version": 1, "status": "pass", "validated": counts}


def check_proposed_contracts(proposal_root: Path | str) -> dict[str, Any]:
    """Parse proposed schemas/policy with protected installed tooling only."""
    root = Path(proposal_root).resolve()
    _reject_repository_binaries(root)
    validate_schema_set(root)
    load_policy_bundle(root)
    return {"schema_version": 1, "status": "pass", "scope": "proposed-contracts-only"}
