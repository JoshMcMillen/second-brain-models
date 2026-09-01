from __future__ import annotations

from pathlib import Path
import re

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = REPO_ROOT / ".github" / "workflows"
PINNED_ACTION = re.compile(r"^actions/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def _workflows() -> list[Path]:
    return sorted(WORKFLOW_ROOT.glob("*.yml"))


def test_expected_workflows_parse_and_pin_every_action() -> None:
    paths = _workflows()
    assert {path.name for path in paths} == {
        "candidate-check.yml",
        "discover.yml",
        "evaluate.yml",
        "publish.yml",
        "revoke.yml",
    }
    for path in paths:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(document, dict)
        for job in document["jobs"].values():
            for step in job.get("steps", []):
                if "uses" in step:
                    assert PINNED_ACTION.fullmatch(step["uses"]), (path.name, step["uses"])
                if "run" in step:
                    assert "${{ inputs." not in step["run"], path.name


def test_privileged_and_candidate_workflows_fail_safe() -> None:
    candidate = (WORKFLOW_ROOT / "candidate-check.yml").read_text(encoding="utf-8")
    assert "pull_request_target" not in candidate
    assert re.search(r"(?m)^  pull_request:\s*$", candidate)
    assert "paths:" not in candidate.split("workflow_dispatch:", 1)[0]

    for name in ("publish.yml", "revoke.yml"):
        text = (WORKFLOW_ROOT / name).read_text(encoding="utf-8")
        assert "contents: read" in text
        assert "FAIL CLOSED:" in text
        assert "git push" not in text

    evaluation = (WORKFLOW_ROOT / "evaluate.yml").read_text(encoding="utf-8")
    assert "evaluate-exact-candidate" in evaluation
    assert re.search(r"(?m)^  push:\s*$", evaluation)
    assert re.search(r'(?m)^      - "models/\*/manifest\.json"\s*$', evaluation)
    assert "github.event_name == 'push'" in evaluation
    assert "Resolve reviewed candidate manifest" in evaluation
    assert "Exactly one added or modified model manifest is required" in evaluation
    assert "git diff --diff-filter=AMR --name-only" in evaluation
    assert "fetch-depth: 0" in evaluation
    assert "model-evaluation-auto" in evaluation
    assert "github.event.repository.default_branch" in evaluation
    assert "DISPATCH_MANIFEST_PATH: ${{ inputs.manifest_path }}" in evaluation
    assert "INPUT_MANIFEST_PATH: ${{ inputs.manifest_path }}" not in evaluation
    assert "disconnected-evaluation-not-yet-enabled" not in evaluation
    assert "sudo unshare" in evaluation
    assert "--mount --net --pid --fork --mount-proc --kill-child=SIGKILL" in evaluation
    assert "--expected-runtime-executable" in evaluation
    assert "EVALUATION_ROOT: /opt/second-brain-evaluation-" in evaluation
    assert "--runtime-scratch-root" in evaluation
    assert "--runtime-root" in evaluation
    assert "extracted-runtime-tree.sha256" in evaluation
    assert "isolated-runtime-tree-pre.sha256" in evaluation
    assert 'sudo chmod o=x "$RUNNER_TEMP"' not in evaluation
    assert 'sudo chmod o+x "$RUNNER_TEMP"' not in evaluation
    assert "sudo -u nobody /usr/bin/test -x" in evaluation
    assert "ref: ${{ github.sha }}" in evaluation
    assert "if: always()" in evaluation
    assert "--require-pass" in evaluation
    assert '--output "$RUNNER_TEMP/results/result.json"' in evaluation
    assert '--output "$RUNNER_TEMP/evidence/result.json"' not in evaluation
    assert "--runner-version 0.2.0" in evaluation
    assert "predictions_artifact_run_id" not in evaluation
