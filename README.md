# Second Brain Models

`second-brain-models` is the separately owned trust and distribution policy repository for local models that may be installed by Second Brain. It does not contain Second Brain application code, model weights, or a remote inference service.

Repository tooling is MIT licensed. Each model and runtime remains governed by the exact upstream license stored beside its quarantined or approved manifest.

The v1 goal is deliberately small:

1. Discover a model only from an allowlisted official publisher.
2. Pin the exact upstream revision and artifact.
3. Review provenance and redistribution terms.
4. Verify the exact artifact's format, size, and SHA-256 digest.
5. Start it without network access, monitor outbound attempts, and run a disconnected smoke test.
6. Run the versioned lightweight quality gate.
7. Require an owner decision before publishing it as beta or stable.
8. Distribute approved, content-addressed artifacts under a signed catalog, from an interim GitHub Releases host today and from Cloudflare R2 once it is enabled.

This repository publishes real, signed catalogs today through `sb-models publish` and GitHub Releases (`docs/publishing-interface-v1.md`), but no production signing key exists yet (`docs/signing-runbook.md`) and no real model has completed owner review, so `beta`/`stable` remain empty. The dedicated `test` channel's contract -- schema, policy, and `sb-models build-canary` -- is in place, so Second Brain will be able to exercise fetch, verify, download, and install end to end against one permanently-fixed, non-model canary fixture; the fixture itself under `fixtures/test-channel/` follows in the next pull request. Until it lands, `publish.yml` skips its `build-canary` step with a notice instead of failing when the `test` channel is dispatched. Quality is calibrated by the artifact's size-derived `lite`, `standard`, or `plus` resource tier and by the tasks it actually passed. Exact provenance, unchanged bytes, no-egress evidence, typed safety responses, zero prompt-injection obedience, and zero authority breaches remain universal gates.

Current candidate evidence:

- Qwen3 0.6B remains held at 3/30 because it is not reliable enough even for the lite tier.
- Qwen3 1.7B remains held despite 21/30 because two authority responses violated the universal safety gate.
- Retained Qwen3 4B outputs meet the proposed standard-beta routing threshold; the model remains quarantined pending a fresh exact run and owner review.

## Trust boundary

```text
Official publisher
       |
       v
GitHub candidate checks -----> private R2 candidate bucket
       |
       v
Owner approval
       |
       v
public R2 release bucket -----> models.avnxmcp.org
       |
       v
signed catalog + exact SHA-256
       |
       v
Second Brain verifies, installs, and runs the model locally
```

Cloudflare stores and delivers public software artifacts. It is not in the inference path. Prompts, documents, embeddings, model output, local database data, and device-linked telemetry must not be sent to this repository or to Cloudflare by the local-model feature.

## V1 decisions

- GitHub holds policy, manifests, exact adjacent license bytes, small evaluation fixtures, summarized results, and catalog files. Each signed manifest binds its committed license to an immutable public `licenses/<sha256>/LICENSE` path by hash and size.
- Model weights are never committed to Git.
- A private R2 bucket stages candidates; a separate public R2 bucket holds approved releases.
- Approved artifacts use immutable paths based on their SHA-256 digest.
- The public release bucket is delivered directly through an R2 custom domain; no Worker is required.
- Each catalog is signed with one Ed25519 release key stored in a protected GitHub publishing environment.
- Publication uploads to a pluggable, explicitly selected asset host (`--host github-release` today; `--host r2` is reserved for later) and always computes final asset URLs before signing, so the signed catalog itself is host-agnostic (`docs/publishing-interface-v1.md`).
- The client strictly parses and canonicalizes catalog JSON, then verifies the detached signature before trusting any field.
- Beta, stable, revoked, and test are explicit signed catalog states; test is a dedicated, non-model connectivity channel outside the promotion ladder.
- V1 does not use TUF, a hardware evaluation matrix, performance qualification, or cloud-hosted inference as proof of local behavior.
- Minimum and recommended hardware values are publisher-supplied claims, clearly labeled as such.
- Published quality scores are recorded with exact-artifact, parent-model, or model-family coverage and never count toward the repository-owned quality score.
- Repository-owned quality thresholds curve by size-derived resource tier and grant only task-scoped suitability labels. They never grant tool authority or override the user's model selection.

## Repository documentation

- [Consumer contract](docs/consumer-contract-v1.md) defines the only interface exported to Second Brain.
- [Cloudflare setup](docs/cloudflare-setup.md) defines the two-bucket and custom-domain configuration.
- [GitHub setup](docs/github-setup.md) records repository protections and deliberately absent release credentials.
- [Promotion policy](docs/promotion-policy.md) defines candidate, beta, stable, rejected, and revoked decisions.
- [Signing runbook](docs/signing-runbook.md) defines catalog signing, verification, rotation, and incident handling.
- [Security policy](SECURITY.md) defines the threat boundary and reporting process.

## Intended repository contents

Future automation may add the following paths without changing the consumer boundary:

```text
policy/                         allowlists and promotion thresholds
schemas/                        manifest, result, and catalog schemas
models/<model-id>/              manifest, LICENSE, and NOTICE
runtimes/<runtime-family>-<version>/
                                 pinned runtime manifest, LICENSE, and provenance
evals/                          small versioned quality fixtures
results/<artifact-sha256>/result.json
                                 summarized exact-artifact result
catalog/                        signed beta, stable, revoked, and test catalogs
fixtures/test-channel/          the one non-model verify-install canary fixture
fixtures/signing/               public fixture key, fixture catalog/signature, and invalid fixtures
.github/workflows/              discovery, checks, publishing, revocation
```

## Contribution rules

- Do not commit model weights, private keys, credentials, raw user content, or model-generated user content.
- Do not add an upstream source without owner approval and an immutable revision.
- Do not execute code supplied by a model repository.
- Add or modify only one model manifest per pull request so its protected-main merge maps to one automatic evaluation.
- Treat runtime packages as untrusted archives until their exact digest, safe extraction, local-only configuration, and no-egress evidence pass review.
- Treat every new artifact, tokenizer, chat template, license change, and quantization as a new candidate.
- Keep workflow code on the protected default branch. Evaluators must not execute code from candidate pull requests.
- Publication requires the protected publishing environment and must upload the artifact before updating the catalog.

## Release meaning

"Approved" is task-specific. It means the exact artifact passed this repository's documented provenance, static, no-egress, disconnected smoke, and lightweight quality checks for the listed tasks. It is not a claim that a model is universally safe, accurate, or suitable for autonomous writes.

See [SECURITY.md](SECURITY.md) before reporting a vulnerability or supply-chain concern.
