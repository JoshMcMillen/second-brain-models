"""Command-line interface for repository automation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from .candidate import check_candidate
from .discovery import discover
from .errors import ModelCatalogError
from .evaluation import evaluate_predictions
from .jsonio import load_json, write_canonical
from .hosting import SUPPORTED_HOSTS
from .lifecycle import build_catalog, create_revocation
from .noegress import collect_no_egress_evidence, merge_no_egress_evidence, probe_no_egress
from .network_monitor import check_strace_logs
from .inference import run_loopback_inference
from .evaluation_stage import stage_evaluation_inputs
from .repository import check_proposed_contracts, check_repository
from .schema import validate_file
from .runtime import validate_runtime_manifest
from .runtime_archive import check_runtime_package, extract_reviewed_llama_runtime
from .signing import (
    generate_keypair, load_private_key, load_public_key, private_key_from_env,
    public_key_id, sign_document, verify_document,
)


def _path(value: str) -> Path:
    return Path(value)


def _print(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sb-models")
    commands = parser.add_subparsers(dest="command", required=True)

    repo = commands.add_parser("repo-check", help="validate all schemas, policies, and repository documents")
    repo.add_argument("--repo-root", type=_path, default=Path.cwd())

    proposal = commands.add_parser("proposed-contract-check", help="parse proposed schemas/policy without executing proposed code")
    proposal.add_argument("--proposal-root", required=True, type=_path)

    validate = commands.add_parser("validate", help="validate one JSON/YAML document against an exact schema")
    validate.add_argument("--repo-root", type=_path, default=Path.cwd())
    validate.add_argument("--kind", required=True, choices=("manifest", "catalog", "result", "revocation", "runtime"))
    validate.add_argument("--document", required=True, type=_path)

    canonical = commands.add_parser("canonicalize", help="write repository canonical JSON")
    canonical.add_argument("--input", required=True, type=_path)
    canonical.add_argument("--output", required=True, type=_path)

    keygen = commands.add_parser("keygen", help="create an Ed25519 release keypair")
    keygen.add_argument("--private", required=True, type=_path)
    keygen.add_argument("--public", required=True, type=_path)

    sign = commands.add_parser("sign", help="write a detached Ed25519 signature over canonical JSON")
    sign.add_argument("--document", required=True, type=_path)
    sign.add_argument("--signature", required=True, type=_path)
    keys = sign.add_mutually_exclusive_group(required=True)
    keys.add_argument("--private-key", type=_path)
    keys.add_argument("--key-env")

    verify = commands.add_parser("verify", help="verify a detached canonical-JSON signature")
    verify.add_argument("--document", required=True, type=_path)
    verify.add_argument("--signature", required=True, type=_path)
    verify.add_argument("--public-key", required=True, type=_path)

    key_id = commands.add_parser("key-id", help="print the trusted Ed25519 public-key fingerprint")
    key_id.add_argument("--public-key", required=True, type=_path)

    candidate = commands.add_parser("candidate-check", help="statically check an exact staged model; never executes it")
    candidate.add_argument("--repo-root", type=_path, default=Path.cwd())
    candidate.add_argument("--manifest", required=True, type=_path)
    candidate.add_argument("--artifact-root", required=True, type=_path)
    candidate.add_argument("--report", type=_path)

    runtime_package = commands.add_parser("runtime-package-check", help="verify a pinned runtime archive without extracting or executing it")
    runtime_package.add_argument("--repo-root", type=_path, default=Path.cwd())
    runtime_package.add_argument("--runtime-manifest", required=True, type=_path)
    runtime_package.add_argument("--package-root", required=True, type=_path)
    runtime_package.add_argument("--platform", required=True)
    runtime_package.add_argument("--report", type=_path)

    runtime_extract = commands.add_parser("runtime-extract", help="guardedly extract the one trusted llama.cpp evaluator runtime")
    runtime_extract.add_argument("--repo-root", type=_path, default=Path.cwd())
    runtime_extract.add_argument("--runtime-manifest", required=True, type=_path)
    runtime_extract.add_argument("--package-root", required=True, type=_path)
    runtime_extract.add_argument("--platform", required=True)
    runtime_extract.add_argument("--destination", required=True, type=_path)

    noegress = commands.add_parser("no-egress-probe", help="capture live disconnected/loopback evidence while runtime is running")
    noegress.add_argument("--runtime-port", required=True, type=int)
    noegress.add_argument("--isolation-id", required=True)
    noegress.add_argument("--output", required=True, type=_path)

    monitor = commands.add_parser("network-monitor-check", help="fail on attempted runtime DNS/TCP/UDP and retain trace digest")
    monitor.add_argument("--network-trace", required=True, type=_path, nargs="+")
    monitor.add_argument("--output", required=True, type=_path)
    monitor.add_argument(
        "--expected-runtime-executable", type=_path,
        help="require the trace to show a successful execve of this exact runtime",
    )

    merge = commands.add_parser("merge-isolation-evidence", help="combine live no-egress and completed monitor receipts")
    merge.add_argument("--probe", required=True, type=_path)
    merge.add_argument("--monitor", required=True, type=_path)
    merge.add_argument("--output", required=True, type=_path)

    infer = commands.add_parser("infer", help="run quality-v1 prompts only against an explicit loopback runtime")
    infer.add_argument("--repo-root", type=_path, default=Path.cwd())
    infer.add_argument("--port", required=True, type=int)
    infer.add_argument("--output", required=True, type=_path)

    evaluate = commands.add_parser("evaluate", help="score raw model outputs against quality-v1 deterministically")
    evaluate.add_argument("--repo-root", type=_path, default=Path.cwd())
    evaluate.add_argument("--manifest", required=True, type=_path)
    evaluate.add_argument("--predictions", required=True, type=_path)
    evaluate.add_argument("--output", required=True, type=_path)
    evaluate.add_argument("--runner-id", default="sb-models-evaluator")
    evaluate.add_argument("--runner-version", default="0.1.0")
    evaluate.add_argument("--runtime-version", required=True)
    evaluate.add_argument("--runtime-platform", required=True)
    evaluate.add_argument("--runtime-package-sha256", required=True)
    evaluate.add_argument("--isolation-id", required=True)
    evaluate.add_argument("--isolation-evidence", required=True, type=_path)
    evaluate.add_argument("--runtime-started-at", required=True)
    evaluate.add_argument("--inference-started-at", required=True)
    evaluate.add_argument("--inference-finished-at", required=True)
    evaluate.add_argument("--runtime-finished-at", required=True)
    evaluate.add_argument(
        "--require-pass", action="store_true",
        help="write the result, then fail when the deterministic quality decision is hold",
    )

    stage = commands.add_parser(
        "evaluation-stage",
        help="download exact public model/runtime inputs and verify pinned size and SHA-256",
    )
    stage.add_argument("--repo-root", type=_path, default=Path.cwd())
    stage.add_argument("--manifest", required=True, type=_path)
    stage.add_argument("--platform", required=True, choices=("linux-x86_64",))
    stage.add_argument("--staging-root", required=True, type=_path)
    stage.add_argument("--receipt", required=True, type=_path)

    isolated = commands.add_parser(
        "isolated-supervisor",
        help="run the exact runtime and synthetic inference inside an unshared Linux namespace",
    )
    isolated.add_argument("--repo-root", type=_path, default=Path.cwd())
    isolated.add_argument("--python-executable", required=True, type=_path)
    isolated.add_argument("--runtime-root", required=True, type=_path)
    isolated.add_argument("--runtime-executable", required=True, type=_path)
    isolated.add_argument("--model", required=True, type=_path)
    isolated.add_argument("--port", required=True, type=int)
    isolated.add_argument("--isolation-id", required=True)
    isolated.add_argument("--supervisor-root", required=True, type=_path)
    isolated.add_argument("--runtime-output-root", required=True, type=_path)
    isolated.add_argument("--runtime-scratch-root", required=True, type=_path)
    isolated.add_argument("--artifact-reader-gid", required=True, type=int)

    discovery = commands.add_parser("discover", help="query allowlisted publisher metadata without downloading or executing content")
    discovery.add_argument("--repo-root", type=_path, default=Path.cwd())
    discovery.add_argument("--output", required=True, type=_path)
    discovery.add_argument("--limit-per-publisher", type=int, default=20)

    catalog = commands.add_parser("build-catalog", help="assemble a reviewed beta/stable catalog")
    catalog.add_argument("--repo-root", type=_path, default=Path.cwd())
    catalog.add_argument("--output", required=True, type=_path)
    catalog.add_argument("--channel", required=True, choices=("beta", "stable", "revoked"))
    catalog.add_argument("--catalog-version", required=True, type=int)
    catalog.add_argument("--public-key", required=True, type=_path)
    catalog.add_argument("--expires-days", type=int, default=7)

    publish = commands.add_parser(
        "publish",
        help="build, sign, upload, verify, and publish one catalog release through a pluggable asset host",
    )
    publish.add_argument("--repo-root", type=_path, default=Path.cwd())
    publish.add_argument(
        "--staging-root", required=True, type=_path,
        help="directory holding verified model/runtime-package bytes at their models/sha256/... and "
        "runtimes/sha256/... paths; never the Git checkout, since those bytes are never committed",
    )
    publish.add_argument("--channel", required=True, choices=("beta", "stable", "revoked"))
    publish.add_argument("--catalog-version", required=True, type=int)
    publish.add_argument("--expires-days", type=int, default=7)
    publish.add_argument("--public-key", required=True, type=_path)
    publish_keys = publish.add_mutually_exclusive_group(required=True)
    publish_keys.add_argument("--private-key", type=_path)
    publish_keys.add_argument("--key-env")
    publish.add_argument("--host", default="github-release", choices=SUPPORTED_HOSTS)
    publish.add_argument("--repository", required=True, help="owner/name of the GitHub repository hosting releases")
    publish.add_argument("--catalog-output", required=True, type=_path)
    publish.add_argument("--signature-output", required=True, type=_path)
    publish.add_argument("--receipt", type=_path)

    revoke = commands.add_parser("revoke", help="create one reviewed revocation record")
    revoke.add_argument("--repo-root", type=_path, default=Path.cwd())
    revoke.add_argument("--manifest", required=True, type=_path)
    revoke.add_argument("--reason-code", required=True)
    revoke.add_argument("--advisory", required=True)
    revoke.add_argument("--review-reference", required=True)
    revoke.add_argument("--replacement-sha256")
    revoke.add_argument("--output", required=True, type=_path)
    return parser


def run(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "repo-check":
        _print(check_repository(args.repo_root))
    elif args.command == "proposed-contract-check":
        _print(check_proposed_contracts(args.proposal_root))
    elif args.command == "validate":
        validate_file(args.document, args.kind, args.repo_root)
        _print({"status": "pass", "kind": args.kind, "document": str(args.document)})
    elif args.command == "canonicalize":
        write_canonical(args.output, load_json(args.input))
    elif args.command == "keygen":
        if args.private.exists() or args.public.exists():
            raise ModelCatalogError("refusing to overwrite an existing key file")
        generate_keypair(args.private, args.public)
    elif args.command == "sign":
        key = load_private_key(args.private_key) if args.private_key else private_key_from_env(args.key_env)
        sign_document(args.document, args.signature, private_key=key)
    elif args.command == "verify":
        verify_document(args.document, args.signature, public_key=load_public_key(args.public_key))
    elif args.command == "key-id":
        print(public_key_id(load_public_key(args.public_key)))
    elif args.command == "candidate-check":
        report = check_candidate(args.manifest, args.artifact_root, args.repo_root)
        if args.report:
            write_canonical(args.report, report)
        _print(report)
    elif args.command == "no-egress-probe":
        evidence = probe_no_egress(runtime_port=args.runtime_port, isolation_id=args.isolation_id)
        write_canonical(args.output, evidence)
        _print(evidence)
    elif args.command == "network-monitor-check":
        monitor = check_strace_logs(
            args.network_trace, expected_runtime_executable=args.expected_runtime_executable,
        )
        write_canonical(args.output, monitor)
        _print(monitor)
    elif args.command == "merge-isolation-evidence":
        evidence = merge_no_egress_evidence(load_json(args.probe), load_json(args.monitor))
        write_canonical(args.output, evidence)
        _print(evidence)
    elif args.command == "infer":
        run_loopback_inference(repo_root=args.repo_root.resolve(), output_path=args.output, port=args.port)
    elif args.command == "runtime-package-check":
        report = check_runtime_package(
            runtime_manifest_path=args.runtime_manifest, package_root=args.package_root,
            platform=args.platform, repo_root=args.repo_root,
        )
        if args.report:
            write_canonical(args.report, report)
        _print(report)
    elif args.command == "runtime-extract":
        executable = extract_reviewed_llama_runtime(
            runtime_manifest_path=args.runtime_manifest, package_root=args.package_root,
            platform=args.platform, repo_root=args.repo_root, destination=args.destination,
        )
        _print({"status": "pass", "executable": str(executable)})
    elif args.command == "evaluate":
        result = evaluate_predictions(
            repo_root=args.repo_root, manifest_path=args.manifest, predictions_path=args.predictions,
            output_path=args.output, runner_id=args.runner_id, runner_version=args.runner_version,
            runtime_version=args.runtime_version, isolation_id=args.isolation_id,
            isolation_evidence=load_json(args.isolation_evidence),
            runtime_platform=args.runtime_platform, runtime_package_sha256=args.runtime_package_sha256,
            runtime_started_at=args.runtime_started_at, inference_started_at=args.inference_started_at,
            inference_finished_at=args.inference_finished_at, runtime_finished_at=args.runtime_finished_at,
        )
        _print(result["decision"])
        if args.require_pass and result["decision"]["evaluation_status"] != "passed":
            raise ModelCatalogError("deterministic quality gate did not pass; result was retained")
    elif args.command == "evaluation-stage":
        receipt = stage_evaluation_inputs(
            repo_root=args.repo_root, manifest_path=args.manifest, platform=args.platform,
            staging_root=args.staging_root, receipt_path=args.receipt,
        )
        _print({
            "status": receipt["status"],
            "model_sha256": receipt["model"]["sha256"],
            "runtime_sha256": receipt["runtime"]["sha256"],
        })
    elif args.command == "isolated-supervisor":
        # POSIX-only imports stay lazy so all other tooling remains portable.
        from .isolated_evaluator import run_isolated_evaluation

        receipt = run_isolated_evaluation(
            repo_root=args.repo_root, python_executable=args.python_executable,
            runtime_root=args.runtime_root, runtime_executable=args.runtime_executable,
            model_path=args.model,
            port=args.port, isolation_id=args.isolation_id,
            supervisor_root=args.supervisor_root,
            runtime_output_root=args.runtime_output_root,
            runtime_scratch_root=args.runtime_scratch_root,
            artifact_reader_gid=args.artifact_reader_gid,
        )
        _print({"status": receipt["status"], "isolation_id": receipt["isolation_id"]})
    elif args.command == "discover":
        _print(discover(args.repo_root, args.output, limit_per_publisher=args.limit_per_publisher))
    elif args.command == "build-catalog":
        key_id = public_key_id(load_public_key(args.public_key))
        catalog = build_catalog(
            repo_root=args.repo_root, output_path=args.output, channel=args.channel,
            catalog_version=args.catalog_version, key_id=key_id, expires_days=args.expires_days,
        )
        _print({"status": "pass", "entries": len(catalog["entries"]), "key_id": key_id})
    elif args.command == "publish":
        if args.host != "github-release":
            raise ModelCatalogError(
                f"host {args.host!r} is not implemented yet; only github-release publishes today"
            )
        from .publishing import GhCliReleaseTransport, publish_release

        key = load_private_key(args.private_key) if args.private_key else private_key_from_env(args.key_env)
        public_key = load_public_key(args.public_key)
        receipt = publish_release(
            repo_root=args.repo_root, staging_root=args.staging_root,
            channel=args.channel, catalog_version=args.catalog_version,
            private_key=key, public_key=public_key, public_key_path=args.public_key,
            repository=args.repository, host=args.host, transport=GhCliReleaseTransport(),
            catalog_output_path=args.catalog_output, signature_output_path=args.signature_output,
            expires_days=args.expires_days, receipt_path=args.receipt,
        )
        _print({
            "status": "pass",
            "release": receipt["release"],
            "objects": len(receipt["objects"]),
            "key_id": receipt["key_id"],
        })
    elif args.command == "revoke":
        _print(create_revocation(
            repo_root=args.repo_root, manifest_path=args.manifest, reason_code=args.reason_code,
            advisory=args.advisory, review_reference=args.review_reference,
            replacement_sha256=args.replacement_sha256, output_path=args.output,
        ))
    return 0


def main() -> None:
    try:
        raise SystemExit(run())
    except (ModelCatalogError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
