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

Likewise, `evaluate.yml` is intentionally disabled for promotion. Imported predictions or syscall logs do not prove local behavior. The enabling implementation must start the exact hash-verified runtime package inside the protected job, disable external networking, begin trusted DNS/TCP/UDP monitoring before runtime startup, run only the synthetic suite through loopback, and stop monitoring only after inference completes.
