from __future__ import annotations

import os
from pathlib import Path

import pytest

from second_brain_models.errors import EvaluationError
from second_brain_models.isolated_evaluator import run_isolated_evaluation


def test_supervisor_refuses_normal_host_process(tmp_path: Path) -> None:
    if os.name == "posix" and os.geteuid() == 0 and os.getpid() == 1:
        pytest.skip("test process is already namespace root")
    with pytest.raises(EvaluationError, match="root PID 1"):
        run_isolated_evaluation(
            repo_root=tmp_path, python_executable=tmp_path / "python",
            runtime_executable=tmp_path / "runtime", model_path=tmp_path / "model",
            port=8080, isolation_id="fixture", supervisor_root=tmp_path / "supervisor",
            runtime_output_root=tmp_path / "runtime-output", artifact_reader_gid=1,
        )


def test_supervisor_source_has_bounded_privilege_and_process_monitor_contract() -> None:
    source = (Path(__file__).resolve().parents[1] / "src" / "second_brain_models" / "isolated_evaluator.py").read_text(encoding="utf-8")
    for required in (
        '"--kill-on-exit"', '"--bounding-set=-all"', '"--no-new-privs"',
        '"--offline"', '"--device", "none"', '"--parallel", "1"',
        "_require_root_owned_read_only", "_require_tracer_running",
        "_capture_direct_tracee", "_stop_traced_runtime", '"shutdown_traced"',
        "_apply_runtime_process_limits", '"process_limits"',
    ):
        assert required in source
