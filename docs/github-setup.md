# GitHub repository setup

The public repository is [JoshMcMillen/second-brain-models](https://github.com/JoshMcMillen/second-brain-models).

## Applied security settings

- GitHub Actions default permissions are read-only; workflows cannot approve pull requests.
- Only GitHub-owned Actions are allowed, and workflow references are pinned to full commit hashes.
- Secret scanning, push protection, dependency vulnerability alerts, Dependabot security updates, and private vulnerability reporting are enabled.
- `model-evaluation` and `model-publish` environments require review by `JoshMcMillen` and accept deployments only from protected branches.
- `CODEOWNERS` assigns the repository to `@JoshMcMillen`.

The intended `main` protection requires a pull request, one CODEOWNER approval, resolved conversations, linear history, and the `untrusted-change-checks` status. Force pushes and branch deletion are disabled. Repository administrators may bypass the pull-request requirement so the solo owner is not permanently deadlocked by the one-review rule; bypasses remain exceptional owner actions.

Machine-readable environment and branch settings are retained under `.github/settings/` for audit and reapplication.

## Deliberately absent

- No production catalog signing key or GitHub signing secret exists. The signing fixture is test-only.
- No R2 credentials exist because R2 is not enabled for the Cloudflare account.
- No workflow can publish, revoke, or qualify a model yet. Those workflows fail closed until their documented same-job evaluation and artifact-first R2 receipts are implemented.
