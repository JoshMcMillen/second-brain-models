# GitHub repository setup

The public repository is [JoshMcMillen/second-brain-models](https://github.com/JoshMcMillen/second-brain-models).

## Applied security settings

- GitHub Actions default permissions are read-only; workflows cannot approve pull requests.
- Only GitHub-owned Actions are allowed, and workflow references are pinned to full commit hashes.
- Secret scanning, push protection, dependency vulnerability alerts, Dependabot security updates, and private vulnerability reporting are enabled.
- `model-evaluation` and `model-publish` require review by `JoshMcMillen` for manual evaluation reruns and publication.
- `model-evaluation-auto` has no reviewer wait and accepts deployments only from protected branches. It is used solely by the read-only post-merge evaluator and has no secrets or publication authority.
- `CODEOWNERS` assigns the repository to `@JoshMcMillen`.

The intended `main` protection requires a pull request, one CODEOWNER approval, resolved conversations, linear history, and the `untrusted-change-checks` status. Force pushes and branch deletion are disabled. Repository administrators may bypass the pull-request requirement so the solo owner is not permanently deadlocked by the one-review rule; bypasses remain exceptional owner actions.

Machine-readable environment and branch settings are retained under `.github/settings/` for audit and reapplication.

## Deliberately absent

- No production catalog signing key or GitHub signing secret exists. The signing fixture is test-only.
- No R2 credentials exist because R2 is not enabled for the Cloudflare account.
- Publishing and revocation remain disabled until their artifact-first R2 receipts are implemented.
- The protected `evaluate.yml` workflow automatically qualifies one exact candidate after its manifest merges to `main`, without R2 or secrets. Manual reruns remain reviewer-gated. Both paths retain the deterministic result and security receipts but cannot commit, publish, or promote anything.
