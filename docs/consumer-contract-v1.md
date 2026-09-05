# Consumer Contract v1

## Purpose

This document defines the complete v1 interface between the separately owned model-distribution project and a future Second Brain installer. The model repository publishes signed, declarative release metadata and immutable artifacts. Second Brain verifies and consumes them; it does not execute repository-supplied installation code.

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## Ownership boundary

The companion model project owns:

- Publisher allowlisting and immutable source provenance.
- License and redistribution review.
- Exact artifact size and SHA-256.
- Format/static checks.
- Monitored no-egress and disconnected smoke results.
- The lightweight quality score and approved read-only tasks.
- Beta, stable, rejected, and revoked release decisions.
- Catalog signing and public artifact delivery.

Second Brain owns:

- The bundled catalog verification public key.
- Catalog signature, expiry, and monotonic-version verification.
- User-facing hardware filtering based on publisher-supplied claims.
- Explicit user approval to download and install.
- Staged download, digest verification, atomic local installation, and rollback.
- User-facing selection and local lifecycle of the pinned runtime and model.
- Outbound-network denial for trusted local inference.
- Validation of all model output and authorization of any host action.

The companion project MUST NOT publish scripts, executable hooks, runtime command arguments, prompts, tools, remote inference endpoints, or instructions that the client executes automatically.

## Public resources

The production hostname is `https://models.avnxmcp.org`.

```text
GET /catalog/v1/stable.json
GET /catalog/v1/stable.json.sig
GET /catalog/v1/beta.json
GET /catalog/v1/beta.json.sig
GET /catalog/v1/revoked.json
GET /catalog/v1/revoked.json.sig
GET /models/sha256/<digest>/model.gguf
GET /runtimes/sha256/<digest>/<platform-package>
GET /results/<digest>/result.json
GET /licenses/<digest>/LICENSE
GET /licenses/<digest>/NOTICE       optional
```

Catalog and signature requests require no user authentication. The client MUST NOT add device identifiers, user identifiers, installed-model telemetry, prompt-derived values, or personal data to paths, query strings, headers, or request bodies.

## Detached signatures

Each `*.json.sig` response contains the standard RFC 4648 base64 encoding of a raw Ed25519 signature. The signature covers the canonical JSON representation of the corresponding document, independent of presentation whitespace or a final newline in the stored file.

Canonical JSON in v1 is:

- Strictly parsed UTF-8 with duplicate keys and non-finite numbers rejected.
- Limited to objects, arrays, strings, integers, booleans, and null; catalog producers MUST NOT emit floating-point values.
- Serialized with object keys in lexicographic order.
- Serialized with compact `,` and `:` separators and no insignificant whitespace.
- Serialized with Unicode preserved rather than ASCII-escaped.
- Encoded as UTF-8 with no trailing newline in the signed bytes.

The client MUST:

1. Fetch the JSON under a conservative metadata-size limit.
2. Strictly parse it only for canonicalization, without acting on any unverified field.
3. Produce the canonical bytes using the v1 rules above.
4. Fetch and base64-decode the detached signature.
5. Verify the signature over the canonical bytes with the v1 Ed25519 public key bundled in the client.
6. Trust and process the parsed values only after verification succeeds.
7. Confirm that `key_id`, `schema_version`, `channel`, and the requested endpoint agree.
8. Reject a catalog version lower than the highest version previously accepted for that channel.
9. Refuse new installation or update from an expired catalog.

If metadata is unavailable, expired, or invalid, an already installed local model MAY continue operating. The client MUST NOT silently use an unsigned catalog or fall back to cloud inference.

## Catalog envelope

The exact JSON Schema will be versioned in `schemas/catalog-v1.schema.json`. The v1 logical shape is:

```json
{
  "schema_version": 1,
  "catalog_id": "second-brain-models",
  "catalog_version": 14,
  "channel": "stable",
  "generated_at": "2026-09-01T18:00:00Z",
  "expires_at": "2026-09-08T18:00:00Z",
  "key_id": "sha256:<64-lowercase-hex-public-key-fingerprint>",
  "promotion_policy": "promotion-v1",
  "distribution": {
    "host": "github-release",
    "release": "catalog-stable-v14"
  },
  "entries": []
}
```

`distribution` is an additive v1 field set by `sb-models publish` (`docs/publishing-interface-v1.md`). Its absence, under the schema_version 1 compatibility rule below, means the catalog was built but not yet published, or was published by tooling that predates this field; the client MUST NOT reject an otherwise-valid catalog for lacking it.

Each installable entry binds repository metadata and evaluation results to exact, schema-validated model and runtime snapshots. The complete nested shapes are defined by `manifest-v1.schema.json` and `runtime-v1.schema.json`:

```json
{
  "manifest_path": "models/example-3b-q4km/manifest.json",
  "manifest_sha256": "<64-lowercase-hex-characters>",
  "result_path": "results/<model-artifact-digest>/result.json",
  "result_sha256": "<64-lowercase-hex-characters>",
  "runtime_manifest_path": "runtimes/example-runtime-1.2.3/manifest.json",
  "runtime_manifest_sha256": "<64-lowercase-hex-characters>",
  "availability": "installable",
  "manifest": {
    "artifact": {
      "path": "models/sha256/<model-artifact-digest>/model.gguf",
      "sha256": "<model-artifact-digest>",
      "size_bytes": 2150000000,
      "format": "gguf",
      "media_type": "application/vnd.gguf"
    },
    "license": {
      "repository_path": "models/example-3b-q4km/LICENSE",
      "path": "licenses/<model-license-digest>/LICENSE",
      "sha256": "<model-license-digest>",
      "size_bytes": 11358
    }
  },
  "runtime_manifest": {
    "license": {
      "repository_path": "runtimes/example-runtime/LICENSE",
      "path": "licenses/<runtime-license-digest>/LICENSE",
      "sha256": "<runtime-license-digest>",
      "size_bytes": 1078
    },
    "packages": [
      {
        "platform": "windows-x86_64",
        "url": "https://models.avnxmcp.org/runtimes/sha256/<runtime-package-digest>/<platform-package>",
        "path": "runtimes/sha256/<runtime-package-digest>/<platform-package>",
        "sha256": "<runtime-package-digest>"
      }
    ]
  },
  "assets": {
    "artifact_url": "https://github.com/<owner>/<repo>/releases/download/catalog-stable-v14/models-sha256-<model-artifact-digest>-model.gguf",
    "license_url": "https://github.com/<owner>/<repo>/releases/download/catalog-stable-v14/licenses-<model-license-digest>-LICENSE",
    "runtime_license_url": "https://github.com/<owner>/<repo>/releases/download/catalog-stable-v14/licenses-<runtime-license-digest>-LICENSE",
    "result_url": "https://github.com/<owner>/<repo>/releases/download/catalog-stable-v14/results-<model-artifact-digest>-result.json",
    "runtime_package_urls": {
      "windows-x86_64": "https://github.com/<owner>/<repo>/releases/download/catalog-stable-v14/runtimes-sha256-<runtime-package-digest>-<platform-package>"
    }
  },
  "revocation": null
}
```

The abbreviated nested objects above illustrate the immutable download fields; actual catalog entries MUST contain every field required by their schemas. Each model and runtime license is committed adjacent to its manifest, then bound to one public `licenses/<sha256>/LICENSE` object by repository path, SHA-256, and byte size. External quality scores are exact decimal strings, not floating-point JSON values. Hardware fields are publisher claims, not measurements by this project. The UI MUST label them accordingly.

`assets` is an additive v1 field, also set by `sb-models publish`, carrying the exact download URL this project already verified for every object this entry references on the catalog's current `distribution.host`. When present, the client SHOULD use these URLs directly rather than deriving a download location from a separately configured base host: they are correct regardless of whether the current host is the interim `github-release` or the eventual production `r2`, and the flattened GitHub Releases filenames (`<flattened-repository-path>`, `/` replaced with `-`) are otherwise not guessable from the manifest alone. Its absence means the same compatibility fallback as `distribution`. Every URL, `assets` or otherwise, still MUST be validated against the [artifact download and verification](#artifact-download-and-verification) rules below -- an `assets` URL is a location, never a substitute for verifying SHA-256 and size against the signed manifest.

The evaluation result records resource-tier-calibrated `eligible_task_contracts`, and the approved manifest may list only a human-reviewed subset. The resource tier is derived from the exact artifact byte size; it is metadata, not a hardware guarantee. These fields communicate tested suitability and may inform defaults. Suggested and approved task labels MUST NOT override the user's model selection or grant tool, write, communication, scheduling, or other host authority.

## Revocation entries

The revoked catalog identifies artifacts that must not be offered for new installation:

```json
{
  "artifact_sha256": "<digest>",
  "model_id": "example-3b-q4km",
  "revoked_at": "2026-09-02T18:00:00Z",
  "reason_code": "security",
  "advisory": "Concise user-facing reason",
  "rollback_sha256": "<known-good-digest-or-null>"
}
```

The client MUST check signed revocations before offering an install or update. Behavior for an already installed revoked model is a Second Brain product-policy decision; the client must at minimum warn clearly and offer the named rollback when present.

## Artifact download and verification

The client MUST:

- Accept only HTTPS URLs on the configured model-distribution origin.
- Require the content-addressed `/models/sha256/<digest>/`, `/runtimes/sha256/<digest>/`, or `/licenses/<digest>/` path to agree with the corresponding manifest digest.
- Reject redirects to an unapproved origin.
- Enforce the declared byte size before and during download.
- Download to a same-volume temporary file.
- Stream SHA-256 verification before the file becomes installable.
- Atomically move the verified file into local content-addressed storage.
- Never execute or import artifact-provided code.
- Verify and retain the exact model and runtime license bytes before installation; never substitute license text fetched outside the signed catalog.
- Leave the currently active model unchanged after a failed or canceled installation.

While the current `distribution.host` is the interim `github-release` (see [Catalog envelope](#catalog-envelope)), a download URL is a `github.com/<owner>/<repo>/releases/download/<release>/<flattened-name>` URL rather than a `models.avnxmcp.org` path, and GitHub's own CDN redirect for a release asset is part of that configured origin for this mode; the content-addressed digest agreement above is enforced by verifying the downloaded bytes' SHA-256 against the manifest digest, since the flattened GitHub Releases filename does not itself carry the `/sha256/<digest>/` path segment. This changes only which origin is configured and how the digest agreement is checked, never the requirement that every downloaded byte is verified against the exact signed manifest value before installation.

R2 ETags are not a substitute for the signed SHA-256 value, especially for multipart uploads.

## Compatibility

V1 consumers MUST reject unknown major `schema_version` values. Additive fields within schema version 1 may be ignored unless marked required by the published JSON Schema. Removing a field or changing its meaning requires a new major contract version.

Catalog versions are monotonically increasing integers within each channel. A beta catalog and stable catalog maintain independent version counters.

## Contract fixtures for Second Brain's own tests

Every catalog release -- `beta`, `stable`, or `revoked`, including an empty one with zero installable entries -- always also attaches this project's versioned JSON Schemas (`schemas/*.json`) and its signing fixtures (`fixtures/signing/`): a valid fixture public key, a valid fixture catalog, its valid detached signature, and at least two invalid fixtures (a bad signature and tampered catalog bytes) a consumer's own tests can assert fail verification. This lets Second Brain's test suite exercise this project's exact schemas and its exact canonicalize/sign/verify behavior -- including the negative cases -- against real committed bytes, without vendoring copies that can drift.

The URL for any of these files follows the same deterministic formula `sb-models publish` uses for every other object (`docs/publishing-interface-v1.md`), and is stable enough for a test suite to construct without an API call:

```text
https://github.com/<owner>/<repo>/releases/download/<release>/<flattened-path>
```

- `<release>` is `catalog-<channel>-v<catalog_version>`, using the exact `channel` and `catalog_version` of a catalog the client has already fetched and signature-verified (never a value the client invents).
- `<flattened-path>` is the file's path relative to the repository root with every `/` replaced by `-` (GitHub Releases assets share one flat namespace and forbid path separators in a filename).

For example, once `catalog-beta-v1` is published, `schemas/catalog-v1.schema.json` and `fixtures/signing/catalog-v1.bad-signature.json.sig` are, respectively:

```text
https://github.com/JoshMcMillen/second-brain-models/releases/download/catalog-beta-v1/schemas-catalog-v1.schema.json
https://github.com/JoshMcMillen/second-brain-models/releases/download/catalog-beta-v1/fixtures-signing-catalog-v1.bad-signature.json.sig
```

These fixture files are not schema-validated catalog entries and carry no signature of their own beyond the ordinary GitHub Release; a test fetching them still MUST verify any digest it independently cares about rather than trusting transport alone.

## Privacy

Catalog checks and artifact downloads necessarily reveal ordinary connection metadata to the distribution provider. They MUST remain independent of inference. The companion project and distribution layer never receive prompts, documents, embeddings, local database records, model output, or content-derived telemetry.
