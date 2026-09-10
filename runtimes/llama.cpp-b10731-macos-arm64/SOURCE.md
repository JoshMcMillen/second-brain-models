# Upstream source

- Repository: https://github.com/ggml-org/llama.cpp
- Release: https://github.com/ggml-org/llama.cpp/releases/tag/b10731
- Revision: `0eadefebd3f8f92a86d634a0e5b8fffc9dc792c0`
- License source: https://raw.githubusercontent.com/ggml-org/llama.cpp/0eadefebd3f8f92a86d634a0e5b8fffc9dc792c0/LICENSE
- Candidate profile: macOS Apple Silicon (`macos-arm64`) only

The exact official package URL, byte size, and SHA-256 are recorded in
`manifest.json`, copied verbatim from the macOS Apple Silicon package entry
already pinned in the shared five-platform manifest
(`runtimes/llama.cpp-b10731/manifest.json`).

Security review: not yet performed. This manifest's `human_review.status` is
`"candidate"` and `no_egress_evidence` is empty. `.github/workflows/runtime-smoke-macos.yml`
is the `workflow_dispatch`-only job that, once run on a `macos-15` (Apple
Silicon) GitHub-hosted runner, is intended to produce the disconnected
smoke-test and no-egress evidence needed to move this profile to `"approved"`
-- mirroring how `runtimes/llama.cpp-b10731-linux-x86_64/manifest.json` was
approved from GitHub Actions run 33554351799's receipts. That workflow run,
the resulting evidence entry, and the `policy/runtime-allowlist.yaml`
addition are a separate, owner-gated follow-up; none of them are part of this
candidate manifest.

Status: candidate macOS Apple Silicon (`macos-arm64`) runtime profile, not
approved. All other upstream platform packages remain outside this profile.
