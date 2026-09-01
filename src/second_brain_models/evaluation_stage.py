"""Download exact public evaluation inputs into a fresh content-addressed staging tree."""
from __future__ import annotations

from contextlib import closing
import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any, BinaryIO
import urllib.error
import urllib.parse
import urllib.request

from .candidate import validate_content_path
from .errors import DocumentError, EvaluationError, PolicyError
from .jsonio import write_canonical
from .license import validate_license_binding
from .policy import load_policy_bundle
from .runtime import validate_model_runtime_reference
from .schema import validate_file


_REVISION = re.compile(r"^[0-9a-f]{40}$")
_CHUNK_SIZE = 1024 * 1024
_MODEL_REDIRECT_HOSTS = {
    "huggingface.co",
    "cdn-lfs.huggingface.co",
    "cdn-lfs-us-1.hf.co",
    "cdn-lfs-eu-1.hf.co",
    "cas-bridge.xethub.hf.co",
}
_RUNTIME_REDIRECT_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


class _RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]) -> None:
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(
        self, req: urllib.request.Request, fp: BinaryIO, code: int, msg: str,
        headers: Any, newurl: str,
    ) -> urllib.request.Request | None:
        parsed = urllib.parse.urlsplit(newurl)
        try:
            allowed_port = parsed.port in {None, 443}
        except ValueError:
            allowed_port = False
        if (
            parsed.scheme != "https" or parsed.hostname not in self.allowed_hosts or not allowed_port
            or parsed.username is not None or parsed.password is not None
        ):
            raise EvaluationError("evaluation download redirected outside the approved HTTPS origins")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _safe_relative(value: str, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or "\\" in value or "\x00" in value:
        raise DocumentError(f"{label} must be a safe POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        raise DocumentError(f"{label} must be a safe POSIX relative path")
    return path


def _model_source_url(manifest: dict[str, Any], repo_root: Path) -> str:
    upstream = manifest["upstream"]
    repository = upstream["repository"]
    policies = load_policy_bundle(repo_root)
    matches = [
        entry for entry in policies["upstream"]["allowed_publishers"]
        if re.fullmatch(entry["repository_pattern"], repository)
    ]
    if len(matches) != 1:
        raise PolicyError("model evaluation source is not exactly allowlisted")
    parts = repository.split("/")
    if len(parts) != 3 or parts[0] != "huggingface.co" or not all(parts[1:]):
        raise PolicyError("v1 evaluation downloads support exact Hugging Face publisher repositories only")
    revision = upstream["revision"]
    if not _REVISION.fullmatch(revision):
        raise PolicyError("model evaluation requires an immutable 40-hex upstream revision")
    source_path = _safe_relative(upstream["source_path"], label="model upstream source_path")
    owner = urllib.parse.quote(parts[1], safe="")
    repository_name = urllib.parse.quote(parts[2], safe="")
    encoded_path = urllib.parse.quote(source_path.as_posix(), safe="/")
    return f"https://huggingface.co/{owner}/{repository_name}/resolve/{revision}/{encoded_path}"


def build_evaluation_plan(
    *, repo_root: Path | str, manifest_path: Path | str, platform: str,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    source = Path(manifest_path).resolve()
    try:
        relative_manifest = source.relative_to(root).as_posix()
    except ValueError as exc:
        raise DocumentError("evaluation manifest must be inside the protected repository") from exc
    if not re.fullmatch(r"models/[a-z0-9][a-z0-9._-]*/manifest\.json", relative_manifest):
        raise DocumentError("evaluation manifest path is not a canonical model manifest path")
    manifest = validate_file(source, "manifest", root)
    validate_license_binding(source, manifest["license"], root)
    runtime = validate_model_runtime_reference(manifest, root, require_approved=False)
    packages = [item for item in runtime["packages"] if item["platform"] == platform]
    if len(packages) != 1:
        raise EvaluationError("runtime manifest must contain exactly one package for the evaluator platform")
    package = packages[0]
    model_relative = validate_content_path(manifest["artifact"]["path"], manifest["artifact"]["sha256"])
    runtime_relative = _safe_relative(package["path"], label="runtime package path")
    executable_relative = _safe_relative(package["executable_path"], label="runtime executable_path")
    return {
        "schema_version": 1,
        "manifest_path": relative_manifest,
        "model": {
            "source_url": _model_source_url(manifest, root),
            "path": model_relative.as_posix(),
            "sha256": manifest["artifact"]["sha256"],
            "size_bytes": manifest["artifact"]["size_bytes"],
        },
        "runtime": {
            "runtime_id": runtime["runtime_id"],
            "version": runtime["version"],
            "platform": package["platform"],
            "source_url": package["upstream_url"],
            "path": runtime_relative.as_posix(),
            "sha256": package["sha256"],
            "size_bytes": package["size_bytes"],
            "format": package["format"],
            "executable_path": executable_relative.as_posix(),
        },
    }


def _download(
    *, source_url: str, target: Path, expected_sha256: str, expected_size: int,
    allowed_hosts: set[str],
) -> str:
    initial = urllib.parse.urlsplit(source_url)
    try:
        initial_port_allowed = initial.port in {None, 443}
    except ValueError:
        initial_port_allowed = False
    if (
        initial.scheme != "https" or initial.hostname not in allowed_hosts or not initial_port_allowed
        or initial.username is not None or initial.password is not None
    ):
        raise EvaluationError("evaluation download source is outside the approved HTTPS origins")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _RestrictedRedirectHandler(allowed_hosts),
    )
    request = urllib.request.Request(
        source_url,
        headers={"Accept-Encoding": "identity", "User-Agent": "second-brain-model-evaluator/1"},
    )
    temporary = target.with_name(target.name + ".part")
    digest = hashlib.sha256()
    total = 0
    final_host = ""
    try:
        target.parent.mkdir(parents=True, exist_ok=False)
        with closing(opener.open(request, timeout=120)) as response, temporary.open("xb") as handle:
            final = urllib.parse.urlsplit(response.geturl())
            try:
                allowed_port = final.port in {None, 443}
            except ValueError:
                allowed_port = False
            if final.scheme != "https" or final.hostname not in allowed_hosts or not allowed_port:
                raise EvaluationError("evaluation download resolved outside the approved HTTPS origins")
            final_host = final.hostname
            declared = response.headers.get("Content-Length")
            if declared is not None:
                try:
                    if int(declared) != expected_size:
                        raise EvaluationError("evaluation download Content-Length differs from the pinned size")
                except ValueError as exc:
                    raise EvaluationError("evaluation download returned an invalid Content-Length") from exc
            while chunk := response.read(_CHUNK_SIZE):
                total += len(chunk)
                if total > expected_size:
                    raise EvaluationError("evaluation download exceeds the pinned size")
                digest.update(chunk)
                handle.write(chunk)
        if total != expected_size:
            raise EvaluationError("evaluation download size differs from the pinned size")
        if digest.hexdigest() != expected_sha256:
            raise EvaluationError("evaluation download SHA-256 differs from the pinned digest")
        temporary.replace(target)
    except (OSError, urllib.error.URLError) as exc:
        raise EvaluationError(f"evaluation download failed: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return final_host


def stage_evaluation_inputs(
    *, repo_root: Path | str, manifest_path: Path | str, platform: str,
    staging_root: Path | str, receipt_path: Path | str,
) -> dict[str, Any]:
    plan = build_evaluation_plan(repo_root=repo_root, manifest_path=manifest_path, platform=platform)
    staging_input = Path(staging_root)
    if staging_input.is_symlink() or (staging_input.exists() and not staging_input.is_dir()):
        raise EvaluationError("evaluation staging root must be a fresh regular directory")
    staging = staging_input.resolve()
    receipt_target = Path(receipt_path).resolve()
    try:
        receipt_target.relative_to(staging)
    except ValueError:
        pass
    else:
        raise EvaluationError("evaluation receipt must be outside the untrusted staging tree")
    if staging.exists() and any(staging.iterdir()):
        raise EvaluationError("evaluation staging root must be fresh and empty")
    staging.mkdir(parents=True, exist_ok=True)
    final_hosts: dict[str, str] = {}
    try:
        for name, allowed_hosts in (("model", _MODEL_REDIRECT_HOSTS), ("runtime", _RUNTIME_REDIRECT_HOSTS)):
            item = plan[name]
            relative = _safe_relative(item["path"], label=f"{name} staging path")
            target = (staging / Path(*relative.parts)).resolve()
            try:
                target.relative_to(staging)
            except ValueError as exc:
                raise EvaluationError(f"{name} staging path escapes the staging root") from exc
            final_hosts[name] = _download(
                source_url=item["source_url"], target=target,
                expected_sha256=item["sha256"], expected_size=item["size_bytes"],
                allowed_hosts=allowed_hosts,
            )
    except Exception:
        # A partial input must never be mistaken for a reviewed staging set.
        shutil.rmtree(staging)
        raise
    receipt = {
        **plan,
        "status": "downloaded-and-hash-verified",
        "model": {**plan["model"], "resolved_host": final_hosts["model"]},
        "runtime": {**plan["runtime"], "resolved_host": final_hosts["runtime"]},
    }
    write_canonical(receipt_target, receipt)
    return receipt
