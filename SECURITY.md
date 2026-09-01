# Security Policy

## Scope

This repository protects the supply chain for optional local models distributed for Second Brain. Security-sensitive components include:

- Upstream publisher and revision allowlists.
- Artifact URLs, byte sizes, and SHA-256 digests.
- License and redistribution decisions.
- Exact-artifact static and disconnected-runtime checks.
- Quality-gate results and task eligibility.
- Catalog generation, Ed25519 signing, and revocation.
- GitHub Actions and Cloudflare R2 publishing credentials.

The repository must never receive Second Brain prompts, documents, embeddings, model output, local database data, credentials, or device-linked telemetry.

## Security guarantees and limits

V1 is designed to detect or constrain:

- Replacement or alteration of a published artifact.
- Accidental use of a mutable upstream reference.
- Unexpected executable or unsafe file types.
- A runtime that cannot start after all network access is removed.
- Observed outbound connection attempts during the monitored smoke test.
- Catalog tampering and simple rollback to an older catalog version.
- Continued installation of an artifact after signed revocation.

V1 does not claim to prove that a model is universally safe, free from malicious learned behavior, or accurate outside its approved tasks. A clean static scan is not proof that a parser has no vulnerability. The Ed25519 v1 design also does not provide TUF's stronger threshold-key and freeze-attack protections.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability, leaked credential, signing-key concern, malicious artifact, or bypass of the no-egress boundary.

Preferred reporting path:

1. Use GitHub's enabled private vulnerability reporting feature for this repository.
2. If private reporting is unavailable, contact the repository owner privately through their verified GitHub profile and disclose only enough information to establish a secure reporting channel.

The repository owner must configure a permanent private security contact before the first public catalog release.

Include, when available:

- Affected model ID, artifact SHA-256, and catalog version.
- Whether the artifact is candidate, beta, stable, or revoked.
- Reproduction steps that do not include private user data.
- Evidence of unexpected network access, unsafe files, signature failure, or digest mismatch.
- Whether active exploitation or credential exposure is suspected.

## Maintainer response

For a credible report, maintainers should:

1. Stop publication workflows if the release path may be compromised.
2. Preserve logs and exact artifact digests without downloading or opening untrusted files on a workstation.
3. Publish a signed revocation when an installable artifact should no longer be offered.
4. Name a known-good rollback artifact when one exists.
5. Rotate the catalog signing key according to [the signing runbook](docs/signing-runbook.md) if key exposure is possible.
6. Rotate affected GitHub or R2 credentials and review repository and Cloudflare audit logs.
7. Publish a concise advisory after containment.

Revocation changes signed catalog state. Published content-addressed objects may remain retained for audit and rollback purposes.

## Supported security surface

Only the latest published catalog schema and current protected default branch receive security fixes. Revoked model artifacts are retained as historical evidence but are not supported for new installation.
