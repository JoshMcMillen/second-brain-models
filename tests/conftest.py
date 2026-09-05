from __future__ import annotations

from pathlib import Path
import hashlib
import json
import shutil
import zipfile

import pytest

from second_brain_models.jsonio import load_json, write_canonical


SOURCE_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy_repo(tmp_path: Path) -> Path:
    for name in ("policy", "schemas", "evals"):
        shutil.copytree(SOURCE_ROOT / name, tmp_path / name)
    shutil.copytree(SOURCE_ROOT / "fixtures" / "signing", tmp_path / "fixtures" / "signing")
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


def _golden_output(case: dict) -> dict:
    """Build one deterministically-passing prediction for a quality-v1 case.

    Generic over every case shape in the suite: every ``field_equals``/
    ``array_equals`` check pins an exact value, and any remaining
    ``field_type``-only field gets a type-correct placeholder.
    """
    exact = next(check["value"] for check in case["expected_checks"] if check["op"] == "json_exact_keys")
    output = {key: None for key in exact}
    for check in case["expected_checks"]:
        if check["op"] in {"field_equals", "array_equals"}:
            output[check["path"].lstrip("/")] = check["value"]
        elif check["op"] == "field_type":
            key = check["path"].lstrip("/")
            if output[key] is None:
                output[key] = {"number": 0.5, "string": "fixture"}[check["value"]]
    return output


def build_installable_candidate(root: Path, staging: Path) -> tuple[Path, Path, Path, Path]:
    """Build one fully genuine, installable "beta"-channel candidate.

    Reuses ``build_candidate()`` for the model/runtime/license shape, then
    does everything a real reviewer would do to make it installable on the
    ``beta`` channel: marks the runtime family's human review "approved" and
    records a matching entry in ``policy/runtime-allowlist.yaml``'s
    ``approved_runtime_manifests`` (mirroring the separate, owner-gated
    runtime approval beta/stable promotion requires), then promotes the
    manifest itself to ``beta``/``approved``. Runs the real quality-v1 suite
    through ``evaluate_predictions()`` with golden outputs to produce a
    genuine passing result, so ``build_catalog(channel="beta")`` picks it up.

    Returns (manifest_path, model_path, runtime_path, result_path).
    """
    import yaml

    from second_brain_models.evaluation import evaluate_predictions, load_suite
    from second_brain_models.policy import load_policy_bundle

    manifest_path, model_path, runtime_path = build_candidate(root, staging)

    runtime = load_json(runtime_path)
    runtime["human_review"] = {
        "required": True, "status": "approved",
        "review_reference": "fixture-runtime-review-1",
    }
    write_canonical(runtime_path, runtime)
    runtime_digest = sha(runtime_path.read_bytes())

    allowlist_path = root / "policy" / "runtime-allowlist.yaml"
    allowlist = yaml.safe_load(allowlist_path.read_text(encoding="utf-8"))
    allowlist["approved_runtime_manifests"] = [{
        "manifest_path": runtime_path.relative_to(root).as_posix(),
        "manifest_sha256": runtime_digest,
        "runtime_id": runtime["runtime_id"],
        "version": runtime["version"],
        "revision": runtime["upstream"]["revision"],
        "decision": "approved",
    }]
    allowlist_path.write_text(yaml.safe_dump(allowlist, sort_keys=False), encoding="utf-8")

    manifest = load_json(manifest_path)
    manifest["runtime"]["manifest_sha256"] = runtime_digest
    manifest["promotion"] = {
        "policy_id": "promotion-v1", "channel": "beta", "status": "approved",
        "human_review_required": True,
        "approved_task_contracts": ["intent_routing-v1", "grounded_summary-v1"],
        "review_reference": "fixture-beta-review-1",
    }
    write_canonical(manifest_path, manifest)

    promotion = load_policy_bundle(root)["promotion"]
    suite = load_suite(root / "evals" / "quality-v1.jsonl", promotion)
    predictions_path = staging / "predictions.jsonl"
    with predictions_path.open("w", encoding="utf-8", newline="\n") as handle:
        for case in suite:
            output_text = json.dumps(_golden_output(case), separators=(",", ":"))
            handle.write(json.dumps({"case_id": case["case_id"], "output_text": output_text}, separators=(",", ":")) + "\n")

    package = runtime["packages"][0]
    artifact_digest = manifest["artifact"]["sha256"]
    result_path = root / "results" / artifact_digest / "result.json"
    evaluate_predictions(
        repo_root=root, manifest_path=manifest_path, predictions_path=predictions_path,
        output_path=result_path, runner_id="fixture-runner", runner_version="1.0.0",
        runtime_version=runtime["version"], runtime_platform=package["platform"],
        runtime_package_sha256=package["sha256"], isolation_id="fixture-evaluation-1",
        isolation_evidence={
            "network_mode": "none", "dns_resolution_available": False,
            "outbound_connectivity_available": False, "default_route_present": False,
            "loopback_runtime_reachable": True, "monitor_method": "strace-network-syscalls",
            "monitor_started_before_runtime": True, "attempted_dns": 0, "attempted_tcp": 0,
            "attempted_udp": 0, "network_attempts_observed": 0,
            "monitor_evidence_sha256": "d" * 64, "verified_at": "2026-09-01T12:04:00Z",
            "isolation_id": "fixture-evaluation-1",
        },
        runtime_started_at="2026-09-01T12:00:00Z", inference_started_at="2026-09-01T12:01:00Z",
        inference_finished_at="2026-09-01T12:03:00Z", runtime_finished_at="2026-09-01T12:04:00Z",
    )
    return manifest_path, model_path, runtime_path, result_path
