# Publishing workflow boundary v1

Signing a catalog is not publication by itself. `publish.yml` used to be intentionally fail-closed after signing because no artifact-first receipt existed. `revoke.yml` still is, for the same reason: revocation has no separate host-selection or upload path yet, and a revoked catalog must not go live without the same discipline.

## Interim host: GitHub Releases (implemented)

`publish.yml` now runs `sb-models publish` (see `second_brain_models/publishing.py` and `second_brain_models/hosting.py`), which produces and verifies exactly the release receipt this document has always required, using GitHub Releases as the asset host while Cloudflare R2 is not yet enabled (`docs/cloudflare-setup.md`):

1. The catalog channel/version determine one immutable release name, `catalog-<channel>-v<catalog_version>`, and every referenced object's final download URL is computed from that name and its own repository-relative path -- deterministically, with no network call.
2. The catalog is built with those URLs already present in each entry's additive `assets` field, then signed. Nothing about the catalog changes after this point.
3. A draft release is created. Every referenced model object, runtime package, model/runtime license, and evaluation result is uploaded to it.
4. Each object is fetched back from the draft release and its byte count and SHA-256 are compared against the exact signed catalog values. R2 ETags (and their GitHub Releases equivalent) are never accepted as digest evidence on their own; this project always recomputes SHA-256 over the fetched bytes.
5. Only after every object verifies does the workflow attach the signed catalog JSON, its detached signature, and the public key to the same release and move it out of draft. Immutable once published: nothing about a published release's assets is rewritten afterward.
6. Any verification failure deletes the draft release and the workflow exits nonzero; the previously published catalog for that channel remains the latest live state.

The release receipt (`--receipt`) is canonical JSON naming the workflow run, channel, catalog version, release name, host, and repository, and listing every *referenced* object's repository path, asset filename, URL, SHA-256, size, and verification result -- models, runtimes, licenses, and results from catalog entries, plus the schemas/fixtures-signing contract fixtures that ride along on every release (`contract_fixture_assets()`). The catalog JSON itself, its detached signature, and the public key are uploaded and byte-verified the same way but are never part of this list; the receipt covers the catalog's own bytes separately, in `catalog_sha256`. The receipt is retained as a workflow artifact.

For an empty catalog (no approved manifest for that channel yet), the referenced-object list is never empty: it still contains the contract fixtures that every release attaches, even though there are no model/runtime/license/result entries. Publication still attaches the catalog, its signature, and the public key, so the channel's signed-but-empty catalog is real and independently verifiable from day one.

## Production host: Cloudflare R2 (documented, not implemented)

`second_brain_models.hosting.resolve_asset_url(host="r2", ...)` is reserved for the eventual move to the production `models.avnxmcp.org` custom domain and fails closed with a pointer to this section until it is implemented. Selecting it will follow the same contract: compute final URLs before signing, sign, upload, re-download and verify, then publish -- see `docs/cloudflare-setup.md` for the two-bucket layout and upload order. Moving from `github-release` to `r2` is a one-line `--host` change at the call site; it does not change the receipt shape, the catalog schema's additive `distribution`/`assets` fields, or the consumer contract.

## Revocation

`revoke.yml` still exits nonzero after signing a revocation record and rebuilding `catalog/revoked.json`: it has no upload/verify path of its own yet. The same `sb-models publish --channel revoked ...` flow used for `beta`/`stable` is the natural next step, gated on the same protected `model-publish` environment; it is not wired into `revoke.yml` in this change.

`evaluate.yml` implements the separate evaluation boundary. A protected manual run downloads the manifest-pinned public upstream model and Linux runtime package, verifies exact size and SHA-256, performs static checks and guarded extraction, and then starts the runtime under `strace` inside one new network/PID/mount namespace. The runtime executes as `nobody` with capabilities removed, a scrubbed environment, bounded OS resources, CPU-only/offline flags, and only a `127.0.0.1` endpoint. The trusted probe and 30-case client run in that same namespace.

The retained trace must show `strace` successfully executing the exact extracted runtime before it can assert `monitor_started_before_runtime`. Any outbound connection or unsupported IPC attempt, non-loopback or wildcard bind, `io_uring` use, `CLONE_UNTRACED`, missing trace evidence, tracer exit during inference, or changed model/runtime bytes fails closed. Results and receipts are uploaded even when the quality gate fails. Evaluation has no R2 or secret dependency and never publishes or promotes a model.
