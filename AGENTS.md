# Contributor guide

This file is for any assistant or person working in this repository. It
exists because the things that go wrong here are expensive and quiet:
committing the wrong bytes, granting an unreviewed capability, or publishing
something that was never actually verified. Read this before changing
anything under `policy/`, `schemas/`, `models/`, `runtimes/`, `catalog/`,
`fixtures/`, `.github/`, or `src/second_brain_models/`.

## What this repository is

`second-brain-models` is the trust and distribution project for local models
that Second Brain may install. It owns:

- Which upstream publishers are even discoverable (`policy/upstream-allowlist.yaml`).
- Review of provenance, license, format, and content-address for one exact
  artifact (`src/second_brain_models/candidate.py`).
- The deterministic, no-model-judge quality gate (`src/second_brain_models/evaluation.py`,
  `evals/quality-v1.jsonl`).
- Signed catalog assembly, publication, and revocation (`src/second_brain_models/lifecycle.py`,
  `publishing.py`, `.github/workflows/`).

Every rule here traces back to one design choice: this project publishes
*declarative, signed metadata and immutable artifacts*. It never publishes
anything Second Brain executes automatically -- no scripts, hooks, runtime
arguments, prompts, or remote endpoints. `docs/consumer-contract-v1.md` is
the normative statement of that boundary; if you are ever unsure whether a
change belongs here or in the Second Brain application, that document
answers it.

## What this repository is not

- **Not model weights.** A `.gguf`, `.safetensors`, `.bin`, or any other
  weight/package format is never committed. `.gitignore` and
  `second_brain_models.repository.check_repository()` both enforce this by
  scanning the whole tree for forbidden suffixes and binary magic bytes; a
  committed model file fails CI outright.
- **Not an inference service.** Nothing here starts, calls, or proxies a
  model. The one place a runtime actually executes a model is the isolated,
  offline `evaluate.yml` workflow, and even that never accepts a live
  connection from outside its own namespace.
- **Not a place for tool, write, or scheduling authority.** `suggested_tasks`
  and `approved_task_contracts` describe tested suitability for read-only
  tasks. They do not grant capability, and nothing in this repository may
  change that (`policy/promotion-v1.yaml`'s `capability_rules` says this in
  the policy itself, and the policy loader rejects a change that weakens it).

## Rules that do not bend

- **Weights never enter Git.** Not as a "just this once" attachment, not
  compressed, not renamed. If a check ever needs real model bytes (candidate
  admission, evaluation, publication), it reads them from an explicit
  staging root or a private bucket that is not this Git repository.
- **A license is committed beside every manifest and bound by hash.** Every
  model and runtime manifest's `license.repository_path` must point at the
  exact adjacent `LICENSE` file, and its `sha256`/`size_bytes` must match
  those exact bytes (`second_brain_models.license.validate_license_binding`).
  Never substitute license text fetched from anywhere else at install time.
- **A manifest enters only through the candidate check.** `sb-models
  candidate-check` is the one static, non-executing gate a new model, a new
  quantization, a new runtime revision, or a license change must pass before
  it is reviewable at all. It never imports, deserializes, or runs anything
  from the candidate. Treat every new artifact, tokenizer, chat template,
  license change, or quantization as a new candidate, not an edit to an old
  one.
- **Revocation only happens through the revoke workflow.** Do not hand-edit
  `catalog/revoked.json` or a manifest's `promotion` block to make a model
  disappear. `revoke.yml` (`sb-models revoke`) creates the signed record and
  rebuilds the channel catalog; it is currently the one workflow still
  deliberately fail-closed after signing (see `docs/publishing-interface-v1.md`)
  because it has no upload/verify path of its own yet.
- **The production signing key exists only in the protected `model-publish`
  environment.** No assistant or person working from this checkout ever
  asks for it, generates it outside the owner's own machine, or prints it.
  `docs/signing-runbook.md` is the one authority on key generation, rotation,
  and compromise response. A throwaway Ed25519 keypair generated inline for
  a test (`second_brain_models.signing.generate_keypair` into a `tmp_path`)
  is fine and expected; anything claiming to be a real release key is not.
- **No personal or employer names beyond what this repository already
  discloses.** The repository owner's GitHub handle already appears
  throughout committed docs, `CODEOWNERS`, and policy (it names this exact
  public repository's own identity, e.g. in `policy/upstream-allowlist.yaml`'s
  self-referential fixture publisher entry). Do not add any other person's
  name, an employer name, an internal system name, or a ticket ID anywhere
  in this repository.
- **Runtime packages are untrusted archives until proven otherwise.**
  `second_brain_models.runtime_archive` is the one guarded extractor; it
  accepts only relative alias chains that stay inside the reviewed archive
  and terminate at a regular file. Do not add another extraction path.
- **Workflow code stays on the protected default branch.** A pull request's
  own `candidate-check.yml` run checks out policy/schema/test code from the
  base commit and only the proposed data files (`models/`, `runtimes/`,
  `results/`, `catalog/`, `revocations/`) from the head commit
  (`untrusted-change-checks` in `candidate-check.yml`). Never make that job
  execute code from the pull request itself.
- **Publication is upload-then-catalog, and the URL is computed before
  anything is signed, never after.** If you touch `sb-models publish`
  (`second_brain_models/publishing.py`, `hosting.py`), keep that order: final
  asset URLs computed from the repository, release name, and asset filename
  alone (no network call) -> catalog built with those URLs already present
  -> catalog signed -> objects uploaded -> every object re-downloaded and
  verified by SHA-256 and size -> only then is the catalog/signature/public
  key attached and the release moved out of draft. Any verification failure
  deletes the draft release; it must never leave a half-published one.

## How a change lands

1. Branch from `main`. One model manifest change per pull request where
   possible, so its post-merge automatic evaluation (`evaluate.yml`) maps to
   exactly one candidate.
2. Open a pull request. `main` requires one CODEOWNER approval, resolved
   conversations, linear history, and a passing required status check.
3. The check GitHub shows on every pull request is **`untrusted-change-checks`**,
   the `pull_request` job in `candidate-check.yml`. It runs `sb-models
   repo-check`, `sb-models proposed-contract-check` against your proposed
   schema/policy files (parsed, never executed, with the repository's own
   protected tooling), and the full `pytest` suite. This is the check that
   must be green before merge.
4. Merging a change to a model manifest under `models/*/manifest.json`
   triggers `evaluate.yml`'s `evaluate-exact-candidate` job automatically
   (read-only, no secrets, no promotion authority). A manual rerun of one
   canonical manifest path is available through the reviewer-protected
   `model-evaluation` environment.
5. Promotion to `beta`/`stable`, catalog publication (`publish.yml`), and
   revocation (`revoke.yml`) are owner-gated, manual `workflow_dispatch` runs
   under the protected `model-publish` environment. No pull request can
   trigger them.
6. Discovery (`discover.yml`, job `discover`) and the pull-request candidate
   check's `exact-artifact-check` job are the only other automated entry
   points; neither can write to the repository or promote anything.

## Running this locally

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    |    POSIX: source .venv/bin/activate
pip install -e ".[test]"

sb-models repo-check --repo-root .
pytest
```

Useful commands while working on a candidate or the tooling itself:

```bash
sb-models validate --kind manifest --document models/<id>/manifest.json
sb-models candidate-check --manifest models/<id>/manifest.json --artifact-root <staging-dir>
sb-models canonicalize --input some.json --output some.canonical.json
sb-models keygen --private /tmp/k.pem --public /tmp/k.pub    # test keys only -- never commit a private key
sb-models sign --document some.json --signature some.json.sig --private-key /tmp/k.pem
sb-models verify --document some.json --signature some.json.sig --public-key /tmp/k.pub
```

`pytest` alone (or `python -m pytest`) runs the whole suite; there is no
separate lint step configured in `pyproject.toml` today. If you add one,
wire it into `candidate-check.yml`'s `untrusted-change-checks` job so it is
part of the one required check, and mention it here.
