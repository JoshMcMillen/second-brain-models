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
  "entries": []
}
```

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
  "revocation": null
}
```

The abbreviated nested objects above illustrate the immutable download fields; actual catalog entries MUST contain every field required by their schemas. Each model and runtime license is committed adjacent to its manifest, then bound to one public `licenses/<sha256>/LICENSE` object by repository path, SHA-256, and byte size. External quality scores are exact decimal strings, not floating-point JSON values. Hardware fields are publisher claims, not measurements by this project. The UI MUST label them accordingly. Suggested tasks are advisory and MUST NOT override the user's model selection or grant tool authority.

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

R2 ETags are not a substitute for the signed SHA-256 value, especially for multipart uploads.

## Compatibility

V1 consumers MUST reject unknown major `schema_version` values. Additive fields within schema version 1 may be ignored unless marked required by the published JSON Schema. Removing a field or changing its meaning requires a new major contract version.

Catalog versions are monotonically increasing integers within each channel. A beta catalog and stable catalog maintain independent version counters.

## Privacy

Catalog checks and artifact downloads necessarily reveal ordinary connection metadata to the distribution provider. They MUST remain independent of inference. The companion project and distribution layer never receive prompts, documents, embeddings, local database records, model output, or content-derived telemetry.
