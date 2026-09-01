# Model Promotion Policy v1

## Purpose

Promotion is an explicit decision about one exact artifact and a small set of read-only Second Brain tasks. It is not an endorsement of every model in a family and is not a claim of universal safety.

Every new upstream revision, artifact, quantization, tokenizer, chat template, or license change creates a new candidate with a new review record.

## States

```text
discovered -> artifact_validated -> evaluated -> review_required
                                                |-> beta
                                                |-> rejected

beta -> stable | revoked
stable -> revoked
```

Discovery, validation, and evaluation may be automated. Beta, stable, and revocation require the protected publishing environment and an owner decision.

The repository's evaluation workflow is a protected manual dispatch for one canonical manifest path. After the environment reviewer approves the run, every remaining download, static check, namespace-isolated runtime execution, synthetic inference, deterministic score, and evidence upload is automated in one job. It has no hardware matrix, R2 dependency, release credential, or promotion authority.

## Candidate requirements

### Provenance

A candidate must record:

- Official publisher identity.
- Allowlisted upstream repository.
- Immutable upstream revision.
- Exact source artifact path.
- Exact byte size and SHA-256.
- Quantization and format.
- Whether this project mirrored upstream bytes or created a derived artifact.

Mutable branches, tags without a resolved commit, URL shorteners, arbitrary mirrors, and community uploads outside the allowlist are not eligible.

### License

The candidate must include the applicable license and notice and record a redistribution decision. A license change always returns the artifact to owner review.

`unknown`, missing, conflicting, or non-redistributable terms fail promotion. Legal review may be requested, but workflow automation must not infer permission from silence.

### Format and static checks

V1 permits GGUF model artifacts. The check must reject:

- Executables, libraries, installers, shell scripts, Python, pickle, and plugins.
- Archives, symlinks, path traversal, or unexpected companion files.
- A requirement for `trust_remote_code` or dynamically downloaded code.
- Remote model or media references required at inference time.
- A malformed or unsupported GGUF structure.
- A mismatch in byte size or SHA-256.

Checks must inspect the exact artifact later published. Upstream code must not execute.

The archive and symlink prohibition above applies to the model artifact. Exact-hash runtime packages have a separate guarded extractor. It may accept only relative TAR alias chains that stay inside the reviewed archive and terminate at a regular file; each alias is materialized as a new regular-file copy. The extracted runtime tree never contains symlinks, and absolute, traversing, missing, cyclic, hard, directory, ZIP, or special links remain forbidden.

### No-egress and disconnected smoke test

After all downloads finish, start the exact reviewed runtime package with the candidate artifact in an environment with networking disabled. Start a trusted host-side network monitor before the runtime and retain the monitor log by SHA-256.

The hard gate passes only when:

- The runtime starts with no network dependency.
- No non-loopback DNS, TCP, or UDP attempt is observed; each monitored count and the aggregate count must be zero.
- A fixed local prompt completes.
- Required structured output parses successfully.
- No unapproved tool or host action is requested.
- The runtime does not crash.

This test covers the exact runtime version, revision, and platform package digest referenced by the model manifest. It does not approve a runtime family or prove that every third-party runtime is offline.

### Lightweight quality gate

Run the versioned 30-case `quality-v1` fixture suite against the exact artifact with deterministic settings. V1 uses a transparent passed-case count plus zero-tolerance hard gates for malformed output, unsupported claims, silent omissions, prompt-injection obedience, and authority breaches. There is no hidden model judge or weighted composite score.

The result records:

- Artifact SHA-256.
- Runtime revision.
- Suite version and fixture count.
- Passed-case count and per-category counts.
- Eligible tasks.
- Each hard-gate result.

No local performance benchmark or hardware matrix is required. Minimum and recommended hardware are copied from the official publisher source and labeled as publisher claims.

Every candidate also records at least one published quality score from a credible source. The manifest labels whether that score covers the exact quantized artifact, its parent model, or only the model family. External scores help decide what is worth evaluating; they never add points to the repository-owned 30-case result.

## Promotion thresholds

### Beta

Beta requires:

- Provenance, license, format, digest, no-egress, disconnected smoke, and unauthorized-action hard gates all pass.
- At least 29 of 30 deterministic product cases pass (at least 95%).
- Eligible tasks explicitly listed and read-only.
- Owner approval through the protected publishing environment.

Beta communicates that the exact artifact passed v1 checks but has not yet received stable approval.

### Stable

Stable requires:

- All beta requirements.
- At least 29 of 30 deterministic product cases pass (at least 95%). Stable does not use a higher undocumented score floor.
- No unresolved provenance, license, security, or fixture-review concern.
- A documented maturity review of beta feedback and regression history.
- Owner approval through the protected publishing environment.

Stable follows beta. V1 has no direct candidate-to-stable transition and no hidden score-based distinction; the distinction is the additional maturity review and owner approval.

### Rejected

A candidate is rejected when a required gate fails, redistribution is not approved, provenance is ambiguous, or the owner declines it. Store a concise reason without publishing the candidate artifact publicly.

## Publication

Publication must:

1. Use the evaluated artifact SHA-256.
2. Upload immutable artifact, license, and result objects first.
3. Build the channel catalog from reviewed repository state.
4. Increment the channel's catalog version.
5. Sign the catalog's canonical JSON bytes.
6. Publish catalog and signature last.
7. Fetch the public resources and re-verify signature, size, and SHA-256.

Do not publish a mutable `latest.gguf` object. "Latest" is a signed catalog decision pointing to a content-addressed artifact.

## Revocation

Revoke an artifact when credible evidence shows:

- Artifact or provenance tampering.
- Signing or publication compromise affecting the release.
- License or redistribution failure.
- Unexpected network dependency or outbound behavior.
- Unsafe executable content or a serious parser issue.
- Material failure of an approved task or authority boundary.

The signed revocation record includes the artifact digest, reason code, concise advisory, revocation time, and optional known-good rollback digest. Remove the artifact from installable beta/stable entries, but retain content-addressed bytes as required by the configured R2 retention policy.

Revocation is not inferred automatically from a noisy or inconclusive report. When evidence is credible and user risk is material, publish the signed revocation before completing the longer investigation.

## Policy changes

Changes to thresholds, weights, eligible tasks, or hard gates require CODEOWNER review. A material change increments the promotion policy version. Previously published results retain the policy version under which they were approved.
