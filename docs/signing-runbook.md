# Catalog Signing Runbook v1

## Purpose

V1 uses one Ed25519 release key to sign canonical catalog JSON. This is intentionally smaller than TUF: it provides catalog authenticity and integrity plus a client-enforced monotonic version and expiry, but not threshold-signature or full freeze-attack protection.

The private key is available only to the protected GitHub `model-publish` environment. The public key is committed to this repository and later bundled into Second Brain through a separate, reviewed application change.

Bootstrap status: the committed key under `fixtures/signing/` is test-only and has no retained private key. No production release public key or signing secret exists yet. Generate and provision the production pair only when R2 publication is ready and the owner explicitly authorizes transfer of the private key to the protected GitHub environment.

## Required owner choices

Before generating the first key, the owner must choose:

- The human or team authorized to approve `model-publish` environment runs.
- The private-key custodian.
- A secure backup location and access policy.
- The catalog expiry interval. Seven days is the proposed v1 default.
- The production model-distribution hostname.

## Signature format

- Algorithm: Ed25519.
- Private-key representation in GitHub: strict base64 containing either an unencrypted PKCS#8 PEM or a raw 32-byte Ed25519 seed.
- Public-key representation: SubjectPublicKeyInfo PEM.
- Detached signature: raw 64-byte Ed25519 signature encoded as standard RFC 4648 base64 in `catalog-name.json.sig`.
- Signed payload: the document's canonical JSON bytes.
- Key ID: `sha256:<64 lowercase hex>`, computed over the raw 32-byte Ed25519 public key by the repository tooling.

Canonical JSON is strict UTF-8 JSON with duplicate keys and non-finite numbers rejected, object keys sorted lexicographically, Unicode preserved, compact `,` and `:` separators, and no trailing newline in the signed bytes. Catalogs use integers rather than floating-point numbers. Presentation whitespace and a final newline in the stored file do not change the signature.

## One-time key creation

Run key generation on a trusted owner-controlled machine with the pinned repository tooling. Do not run it in a pull request, shared shell, or captured terminal session.

```powershell
sb-models keygen --private keys/private/catalog-release-v1.pem --public keys/public/catalog-release-v1.pem
```

Confirm the committed public key loads and record the repository-defined raw-key fingerprint:

```powershell
sb-models key-id --public-key keys/public/catalog-release-v1.pem
```

Then:

1. Strict-base64 encode `keys/private/catalog-release-v1.pem` and store the result as the protected environment secret `CATALOG_SIGNING_KEY_B64`.
2. Store a separately protected recovery copy according to the owner's key-custody decision.
3. Securely remove the working private-key file after both copies are verified.
4. Commit only `keys/public/catalog-release-v1.pem`.
5. Record the raw public-key SHA-256 fingerprint emitted by `sb-models key-id` in the pull request and consumer contract implementation notes.
6. Set the protected environment variable or secret `CATALOG_KEY_ID` to the SHA-256 public-key fingerprint emitted by the repository tooling.

Private key files match this repository's `.gitignore`, but ignore rules are not a security control. Check `git status` before every commit.

## Manual signing verification

The repository tooling canonicalizes before signing and verifying. For a local test key:

```powershell
sb-models canonicalize --input stable.json --output stable.canonical.json
sb-models sign --document stable.json --signature stable.json.sig --private-key release-v1-private.pem
```

Verify before publication:

```powershell
sb-models verify --document stable.json --signature stable.json.sig --public-key release-v1-public.pem
```

Verification must report success. Repeat for beta and revoked catalogs.

## Publishing procedure

The protected workflow must:

1. Build schema-valid UTF-8 JSON and canonicalize it with the repository's single canonicalization implementation.
2. Validate it against the versioned catalog schema.
3. Confirm `catalog_version` is greater than the currently published version for that channel.
4. Set `generated_at`, `expires_at`, and `key_id`.
5. Sign the canonical JSON bytes using `CATALOG_SIGNING_KEY_B64`.
6. Upload all immutable referenced objects before the catalog.
7. Upload catalog JSON and detached signature last.
8. Download both through the public custom domain.
9. Strictly parse and canonicalize the downloaded JSON, then verify its signature, catalog version, expiry, artifact size, and artifact SHA-256.

Never log the private key, secret environment value, or command environment. Do not upload signing material to R2.

`sb-models publish` implements steps 6-9 for the interim `github-release` host (`docs/publishing-interface-v1.md`): every referenced model, runtime, license, and result object is individually re-downloaded and its byte size and SHA-256 re-verified, in addition to the catalog and signature themselves, before the draft release is moved out of draft. Any verification failure deletes the draft release rather than leaving a half-published one.

## Catalog expiry and rollback

Each channel has its own monotonically increasing `catalog_version`. A client remembers the highest accepted version and rejects lower versions.

The proposed v1 expiry is seven days. When a catalog expires:

- Existing installed models may continue to work.
- The client refuses new installation or update from that catalog.
- The client reports that release metadata could not be refreshed.
- The client does not accept unsigned metadata or silently fall back to cloud inference.

A rollback is a new, higher-version signed catalog that points to a previously approved content-addressed artifact. Never republish an older catalog version as current.

## Routine key rotation

Key rotation requires coordination with Second Brain because the verification key is bundled with the application:

1. Generate a new key and proposed key ID.
2. Add the new public key to Second Brain while it still trusts the old key.
3. Release that client version.
4. Update this repository's public keys and publishing secret through protected owner actions.
5. Publish catalogs with the new key only after supported clients trust it.
6. Retain the old public key for verification history; remove the old private key from active publishing secrets.

V1 does not support remote trust of an unrecognized replacement key.

## Suspected compromise

If private-key exposure is suspected:

1. Disable all publication workflows and remove access to the `model-publish` environment.
2. Delete or replace `CATALOG_SIGNING_KEY_B64` so the suspected key cannot be used by Actions.
3. Rotate R2 release credentials if the publication environment may also be compromised.
4. Preserve GitHub and Cloudflare audit evidence.
5. Determine the last known-good catalog version and artifact set.
6. Ship a Second Brain update containing a new trusted public key.
7. Resume publication with a higher catalog version and the new key.
8. Publish an advisory describing affected versions and required client action.

Because v1 has one online publication key, key compromise cannot be repaired safely by publishing a new key signed only by the compromised key. Client trust must be updated through the independently distributed Second Brain application.
