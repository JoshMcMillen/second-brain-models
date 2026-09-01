# Publishing workflow boundary v1

The `publish.yml` and `revoke.yml` workflows are intentionally fail-closed before they mutate Git. Signing a catalog is not publication by itself.

Before those gates may be enabled, a protected-environment implementation must produce and verify one release receipt that proves, in order:

1. Every model object was uploaded to `models/sha256/<digest>/model.gguf`.
2. Every runtime package was uploaded to `runtimes/sha256/<digest>/<platform-package>`.
3. Every model and runtime license was read from the manifest-adjacent repository `LICENSE`, matched its signed repository path, byte size, and SHA-256, and was uploaded to `licenses/<sha256>/LICENSE` before any catalog.
4. Each object was fetched again through `https://models.avnxmcp.org` with redirects disabled.
5. The fetched byte count and SHA-256 matched the exact signed manifest/catalog values.
6. The new signed channel catalog and detached signature were uploaded last and fetched back for Ed25519 verification.

The receipt must be canonical JSON, name the protected workflow run and channel/catalog version, list each public URL, byte size, SHA-256, and verification result, and itself be retained as a workflow artifact. R2 ETags are not acceptable digest evidence. Until this interface exists, the workflows exit nonzero and do not commit release or revocation state.

`evaluate.yml` implements the separate evaluation boundary. A protected manual run downloads the manifest-pinned public upstream model and Linux runtime package, verifies exact size and SHA-256, performs static checks and guarded extraction, and then starts the runtime under `strace` inside one new network/PID/mount namespace. The runtime executes as `nobody` with capabilities removed, a scrubbed environment, bounded OS resources, CPU-only/offline flags, and only a `127.0.0.1` endpoint. The trusted probe and 30-case client run in that same namespace.

The retained trace must show `strace` successfully executing the exact extracted runtime before it can assert `monitor_started_before_runtime`. Any outbound connection or unsupported IPC attempt, non-loopback or wildcard bind, `io_uring` use, `CLONE_UNTRACED`, missing trace evidence, tracer exit during inference, or changed model/runtime bytes fails closed. Results and receipts are uploaded even when the quality gate fails. Evaluation has no R2 or secret dependency and never publishes or promotes a model.
