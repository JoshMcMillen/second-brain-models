from __future__ import annotations

from pathlib import Path
import hashlib
import shutil
import zipfile

import pytest

from second_brain_models.jsonio import write_canonical


SOURCE_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy_repo(tmp_path: Path) -> Path:
    for name in ("policy", "schemas", "evals"):
        shutil.copytree(SOURCE_ROOT / name, tmp_path / name)
    return tmp_path


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def build_candidate(root: Path, staging: Path) -> tuple[Path, Path, Path]:
    temporary = staging / "runtime.zip"
    temporary.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
        info = zipfile.ZipInfo("bin/llama-server")
        info.external_attr = 0o100755 << 16
        archive.writestr(info, b"reviewed runtime fixture")
    package_raw = temporary.read_bytes()
    package_digest = sha(package_raw)
    package_path = staging / "runtimes" / "sha256" / package_digest / "llama-linux-x86_64.zip"
    package_path.parent.mkdir(parents=True)
    temporary.replace(package_path)
    runtime_dir = root / "runtimes" / "llama.cpp-1.2.3"
    runtime_license = b"Fixture MIT license bytes\n"
    runtime_license_path = runtime_dir / "LICENSE"
    runtime_license_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_license_path.write_bytes(runtime_license)
    runtime_license_digest = sha(runtime_license)
    runtime = {
        "schema_version": 1, "runtime_id": "llama.cpp-server", "version": "1.2.3",
        "upstream": {"repository": "github.com/ggml-org/llama.cpp", "revision": "b" * 40},
        "api_contract": "openai-chat-completions-loopback",
        "license": {
            "spdx": "MIT", "upstream_file": "LICENSE",
            "repository_path": "runtimes/llama.cpp-1.2.3/LICENSE",
            "path": f"licenses/{runtime_license_digest}/LICENSE",
            "sha256": runtime_license_digest, "size_bytes": len(runtime_license),
            "redistribution_allowed": True, "commercial_use_allowed": True,
            "attribution_required": True, "notice_files": [],
        },
        "packages": [{
            "platform": "linux-x86_64",
            "upstream_url": "https://github.com/ggml-org/llama.cpp/releases/download/v1.2.3/llama-linux-x86_64.zip",
            "url": f"https://models.avnxmcp.org/runtimes/sha256/{package_digest}/llama-linux-x86_64.zip",
            "path": f"runtimes/sha256/{package_digest}/llama-linux-x86_64.zip",
            "sha256": package_digest, "size_bytes": len(package_raw), "format": "zip",
            "media_type": "application/zip", "executable_path": "bin/llama-server",
        }],
        "local_only": {
            "bind_hosts": ["127.0.0.1"], "telemetry_enabled": False,
            "runtime_discovery_enabled": False, "automatic_model_pull_enabled": False,
            "remote_backend_enabled": False, "cloud_offload_enabled": False,
            "cloud_fallback_enabled": False,
        },
        "no_egress_evidence": [{
            "platform": "linux-x86_64", "package_sha256": package_digest,
            "network_mode": "none", "monitor_method": "strace-network-syscalls",
            "monitor_started_before_runtime": True, "network_attempts_observed": 0,
            "attempted_dns": 0, "attempted_tcp": 0, "attempted_udp": 0,
            "monitor_evidence_sha256": "c" * 64, "loopback_runtime_reachable": True,
            "verified_at": "2026-09-01T12:00:00Z", "isolation_id": "fixture-runtime-1",
        }],
        "human_review": {"required": True, "status": "candidate", "review_reference": None},
    }
    runtime_path = runtime_dir / "manifest.json"
    write_canonical(runtime_path, runtime)
    runtime_digest = sha(runtime_path.read_bytes())
    model_raw = b"GGUF" + (3).to_bytes(4, "little") + (0).to_bytes(8, "little") + (0).to_bytes(8, "little")
    model_digest = sha(model_raw)
    model_path = staging / "models" / "sha256" / model_digest / "model.gguf"
    model_path.parent.mkdir(parents=True)
    model_path.write_bytes(model_raw)
    suite_path = root / "evals" / "quality-v1.jsonl"
    model_dir = root / "models" / "fixture-model"
    model_license = b"Fixture Apache-2.0 license bytes\n"
    model_license_path = model_dir / "LICENSE"
    model_license_path.parent.mkdir(parents=True, exist_ok=True)
    model_license_path.write_bytes(model_license)
    model_license_digest = sha(model_license)
    manifest = {
        "schema_version": 1, "model_id": "fixture-model", "release": "r1",
        "display_name": "Fixture Model", "tier": "lite", "quantization": "Q4_K_M",
        "upstream": {"repository": "huggingface.co/openai/fixture-model", "revision": "a" * 40, "source_path": "model.gguf"},
        "artifact": {"path": f"models/sha256/{model_digest}/model.gguf", "sha256": model_digest, "size_bytes": len(model_raw), "format": "gguf", "media_type": "application/vnd.gguf"},
        "license": {
            "spdx": "Apache-2.0", "upstream_file": "LICENSE",
            "repository_path": "models/fixture-model/LICENSE",
            "path": f"licenses/{model_license_digest}/LICENSE",
            "sha256": model_license_digest, "size_bytes": len(model_license),
            "redistribution_allowed": True, "commercial_use_allowed": True,
            "attribution_required": True, "notice_files": [],
        },
        "runtime": {"runtime_id": "llama.cpp-server", "version": "1.2.3", "revision": "b" * 40, "manifest_path": "runtimes/llama.cpp-1.2.3/manifest.json", "manifest_sha256": runtime_digest, "api_contract": "openai-chat-completions-loopback", "allowlist_policy": "runtime-allowlist-v1"},
        "evaluation": {"suite_id": "quality-v1", "suite_sha256": sha(suite_path.read_bytes()), "policy_id": "promotion-v1", "result_path": f"results/{model_digest}/result.json", "task_contracts": ["intent_routing-v1", "grounded_summary-v1", "grounded_answer-v1", "safety_boundary-v1"]},
        "external_quality_evidence": [{"source_url": "https://huggingface.co/openai/fixture-model", "source_kind": "publisher_report", "reported_model": "Fixture Model", "coverage": "parent_model", "benchmark": "Public synthetic benchmark", "metric": "accuracy", "score": "0.9", "higher_is_better": True}],
        "suggested_tasks": ["routing"], "suggested_tasks_advisory": True,
        "hardware": {"publisher_minimum": None, "publisher_recommended": None},
        "promotion": {"policy_id": "promotion-v1", "channel": "candidate", "status": "quarantined", "human_review_required": True, "approved_task_contracts": []},
    }
    manifest_path = model_dir / "manifest.json"
    write_canonical(manifest_path, manifest)
    return manifest_path, model_path, runtime_path
