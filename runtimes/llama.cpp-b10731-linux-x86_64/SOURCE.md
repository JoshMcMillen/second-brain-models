# Upstream source

- Repository: https://github.com/ggml-org/llama.cpp
- Release: https://github.com/ggml-org/llama.cpp/releases/tag/b10731
- Revision: `0eadefebd3f8f92a86d634a0e5b8fffc9dc792c0`
- License source: https://raw.githubusercontent.com/ggml-org/llama.cpp/0eadefebd3f8f92a86d634a0e5b8fffc9dc792c0/LICENSE
- Approved profile: Linux x86-64 only

The exact official package URL, byte size, and SHA-256 are recorded in `manifest.json`.

Security review: [GitHub Actions run 33554351799](https://github.com/JoshMcMillen/second-brain-models/actions/runs/33554351799) validated the exact Linux x86-64 package, ran it as an unprivileged identity in a disconnected network namespace, observed zero DNS/TCP/UDP attempts across the traced process tree, and revalidated unchanged bytes after inference.

Status: approved Linux x86-64 runtime profile. All other upstream platform packages remain outside this approved profile.
