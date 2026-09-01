"""Trusted same-job supervisor for one disconnected Linux evaluation run."""
from __future__ import annotations

from datetime import datetime, timezone
import http.client
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import time
from typing import Any

try:  # The command is Linux-only; the rest of the CLI remains cross-platform.
    import pwd
    import resource
except ImportError:  # pragma: no cover - exercised by Windows import tests
    pwd = None  # type: ignore[assignment]
    resource = None  # type: ignore[assignment]

from .errors import EvaluationError
from .jsonio import write_canonical


_TRACE_EXPRESSION = "trace=%network,%process,io_uring_setup,io_uring_enter,io_uring_register"
_PROCESS_LIMITS = {
    "address_space_bytes": 24 * 1024 * 1024 * 1024,
    "cpu_seconds": 2_400,
    "file_bytes": 16 * 1024 * 1024,
    "open_files": 1_024,
    "processes": 256,
}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _require_fresh_directory(path: Path, *, mode: int) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise EvaluationError(f"isolated evaluator path is not a fresh regular directory: {path}")
    if path.exists() and any(path.iterdir()):
        raise EvaluationError(f"isolated evaluator directory must be fresh and empty: {path}")
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def _wait_for_health(port: int, runtime: subprocess.Popen[bytes], *, timeout_seconds: int = 300) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if runtime.poll() is not None:
            raise EvaluationError("reviewed runtime exited before its loopback health check passed")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            response.read(64 * 1024)
            if response.status == 200:
                return
        except OSError:
            pass
        finally:
            connection.close()
        time.sleep(1)
    raise EvaluationError("reviewed runtime did not become healthy on loopback before timeout")


def _emergency_stop(tracer: subprocess.Popen[bytes]) -> None:
    if tracer.poll() is not None:
        return
    try:
        os.killpg(tracer.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        tracer.wait(timeout=10)
    except subprocess.TimeoutExpired:
        raise EvaluationError("could not stop the runtime tracer process group")


def _capture_direct_tracee(tracer: subprocess.Popen[bytes], *, timeout_seconds: int = 10) -> int:
    children_path = Path(f"/proc/{tracer.pid}/task/{tracer.pid}/children")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if tracer.poll() is not None:
            raise EvaluationError("runtime tracer exited before its direct tracee was recorded")
        try:
            children = [int(value) for value in children_path.read_text(encoding="ascii").split()]
        except (OSError, ValueError):
            children = []
        if len(children) == 1:
            return children[0]
        if len(children) > 1:
            raise EvaluationError("runtime tracer has an ambiguous direct tracee set")
        time.sleep(0.05)
    raise EvaluationError("runtime tracer direct tracee was not observable before timeout")


def _stop_traced_runtime(tracer: subprocess.Popen[bytes], tracee_pid: int) -> int:
    _require_tracer_running(tracer, "before traced shutdown")
    try:
        status = Path(f"/proc/{tracee_pid}/status").read_text(encoding="ascii")
        parent_line = next(line for line in status.splitlines() if line.startswith("PPid:"))
        parent_pid = int(parent_line.split()[1])
    except (OSError, StopIteration, ValueError) as exc:
        raise EvaluationError("could not verify the exact direct tracee before shutdown") from exc
    if parent_pid != tracer.pid:
        raise EvaluationError("runtime tracee is no longer the tracer's exact direct child")
    try:
        os.kill(tracee_pid, signal.SIGTERM)
    except ProcessLookupError as exc:
        raise EvaluationError("runtime tracee disappeared before monitored shutdown") from exc
    try:
        exit_code = tracer.wait(timeout=30)
    except subprocess.TimeoutExpired as exc:
        _emergency_stop(tracer)
        raise EvaluationError("runtime did not complete traced graceful shutdown") from exc
    if exit_code != 0:
        raise EvaluationError(f"runtime tracer reported nonzero shutdown status {exit_code}")
    return exit_code


def _require_tracer_running(runtime: subprocess.Popen[bytes], phase: str) -> None:
    if runtime.poll() is not None:
        raise EvaluationError(f"runtime tracer exited {phase}; evaluation is untrusted")


def _require_root_owned_read_only(path: Path, label: str, *, executable: bool) -> None:
    metadata = path.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise EvaluationError(f"{label} must be root-owned and not group/other-writable")
    if executable and not metadata.st_mode & 0o111:
        raise EvaluationError(f"{label} must remain executable")


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _require_root_owned_runtime_tree(runtime_root: Path, runtime_binary: Path) -> None:
    if not runtime_root.is_dir():
        raise EvaluationError("reviewed runtime root is missing or not a directory")
    try:
        runtime_binary.relative_to(runtime_root)
    except ValueError as exc:
        raise EvaluationError("runtime executable must be inside the reviewed runtime root") from exc

    for current_root, directory_names, file_names in os.walk(runtime_root, followlinks=False):
        current = Path(current_root)
        members = [current, *(current / name for name in directory_names), *(current / name for name in file_names)]
        for member in members:
            metadata = member.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise EvaluationError(f"reviewed runtime tree contains a symlink: {member}")
            if stat.S_ISDIR(metadata.st_mode):
                if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise EvaluationError(f"reviewed runtime directory is not root-owned read-only: {member}")
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise EvaluationError(f"reviewed runtime tree contains a special file: {member}")
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise EvaluationError(f"reviewed runtime file is not root-owned read-only: {member}")


def _run_trusted(command: list[str], *, environment: dict[str, str], timeout: int) -> None:
    try:
        subprocess.run(
            command, check=True, timeout=timeout, env=environment,
            stdin=subprocess.DEVNULL, close_fds=True,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise EvaluationError(f"isolated evaluator child failed: {command[-1]}: {exc}") from exc


def _apply_runtime_process_limits() -> None:
    """Bound the tracer and every inherited runtime process before first exec."""
    if resource is None:  # pragma: no cover - guarded by the Linux-only caller
        raise RuntimeError("POSIX resource limits are unavailable")
    limits = (
        (resource.RLIMIT_AS, _PROCESS_LIMITS["address_space_bytes"]),
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_CPU, _PROCESS_LIMITS["cpu_seconds"]),
        (resource.RLIMIT_FSIZE, _PROCESS_LIMITS["file_bytes"]),
        (resource.RLIMIT_NOFILE, _PROCESS_LIMITS["open_files"]),
        (resource.RLIMIT_NPROC, _PROCESS_LIMITS["processes"]),
    )
    for kind, value in limits:
        resource.setrlimit(kind, (value, value))


def run_isolated_evaluation(
    *, repo_root: Path | str, python_executable: Path | str,
    runtime_root: Path | str, runtime_executable: Path | str,
    model_path: Path | str, port: int,
    isolation_id: str, supervisor_root: Path | str, runtime_output_root: Path | str,
    runtime_scratch_root: Path | str, artifact_reader_gid: int,
) -> dict[str, Any]:
    """Run a dropped-privilege runtime and trusted client in one namespace.

    The caller must exec this supervisor as PID 1 in a fresh network, PID, and
    mount namespace.  The runtime is a direct child of strace, so the exact
    successful execve in the trace proves monitoring began before runtime code.
    """
    if os.name != "posix" or os.geteuid() != 0 or os.getpid() != 1:
        raise EvaluationError("isolated evaluator must run as root PID 1 in a new Linux PID namespace")
    try:
        interfaces = {name for _, name in socket.if_nameindex()}
    except OSError as exc:
        raise EvaluationError("isolated evaluator could not enumerate namespace interfaces") from exc
    if interfaces != {"lo"}:
        raise EvaluationError("isolated evaluator requires a fresh network namespace containing only loopback")
    if not 1 <= port <= 65535:
        raise EvaluationError("isolated evaluator loopback port is invalid")
    if artifact_reader_gid <= 0:
        raise EvaluationError("artifact reader group must be a non-root group")

    root = Path(repo_root).resolve()
    python = Path(python_executable).resolve()
    runtime_root_input = Path(runtime_root)
    runtime_input = Path(runtime_executable)
    model_input = Path(model_path)
    if runtime_root_input.is_symlink() or runtime_input.is_symlink() or model_input.is_symlink():
        raise EvaluationError("isolated evaluator refuses symlink runtime/model inputs")
    reviewed_runtime_root = runtime_root_input.resolve()
    runtime_binary = runtime_input.resolve()
    model = model_input.resolve()
    if not python.is_file() or not runtime_binary.is_file() or not model.is_file():
        raise EvaluationError("isolated evaluator input executable or model is missing")
    _require_root_owned_read_only(runtime_binary, "runtime executable", executable=True)
    _require_root_owned_read_only(model, "model artifact", executable=False)
    _require_root_owned_runtime_tree(reviewed_runtime_root, runtime_binary)

    trusted_path = "/usr/sbin:/usr/bin:/sbin:/bin"
    strace = shutil.which("strace", path=trusted_path)
    ip = shutil.which("ip", path=trusted_path)
    env_binary = shutil.which("env", path=trusted_path)
    setpriv = shutil.which("setpriv", path=trusted_path)
    if not strace or not ip or not env_binary or not setpriv:
        raise EvaluationError("isolated evaluator requires strace, ip, env, and setpriv")

    supervisor_input = Path(supervisor_root)
    runtime_output_input = Path(runtime_output_root)
    runtime_scratch_input = Path(runtime_scratch_root)
    if (
        supervisor_input.is_symlink()
        or runtime_output_input.is_symlink()
        or runtime_scratch_input.is_symlink()
    ):
        raise EvaluationError("isolated evaluator refuses symlink output roots")
    supervisor = supervisor_input.resolve()
    runtime_output = runtime_output_input.resolve()
    runtime_scratch = runtime_scratch_input.resolve()
    output_roots = (supervisor, runtime_output, runtime_scratch)
    if any(
        _paths_overlap(left, right)
        for index, left in enumerate(output_roots)
        for right in output_roots[index + 1:]
    ):
        raise EvaluationError("isolated evaluator output and scratch roots must not overlap")
    _require_fresh_directory(supervisor, mode=0o750)
    _require_fresh_directory(runtime_output, mode=0o750)
    os.chown(supervisor, 0, artifact_reader_gid)
    os.chown(runtime_output, 0, artifact_reader_gid)
    trace_root = supervisor / "strace"
    trace_root.mkdir(mode=0o750)
    os.chown(trace_root, 0, artifact_reader_gid)
    server_log = supervisor / "llama-server.log"
    receipt_path = supervisor / "supervisor.json"

    if pwd is None or resource is None:
        raise EvaluationError("isolated evaluator requires the POSIX account and resource-limit APIs")
    nobody = pwd.getpwnam("nobody")
    _require_fresh_directory(runtime_scratch, mode=0o700)
    os.chown(runtime_scratch, nobody.pw_uid, nobody.pw_gid)
    trusted_home = runtime_output / "trusted-home"
    trusted_home.mkdir(mode=0o700)
    predictions = runtime_output / "predictions.jsonl"
    probe = runtime_output / "probe.json"

    try:
        subprocess.run(
            [ip, "link", "set", "lo", "up"], check=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise EvaluationError(f"could not enable loopback in isolated namespace: {exc}") from exc

    runtime_environment = {
        "HOME": str(runtime_scratch),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LD_LIBRARY_PATH": str(runtime_binary.parent),
        "PATH": "/usr/bin:/bin",
        "SB_MODELS_NETWORK_MODE": "none",
        "TMPDIR": str(runtime_scratch),
    }
    trusted_environment = {
        "HOME": str(trusted_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONUTF8": "1",
        "SB_MODELS_NETWORK_MODE": "none",
        "TMPDIR": str(trusted_home),
    }
    trace_prefix = trace_root / "runtime"
    runtime_command = [
        strace, "-qq", "-ff", "--kill-on-exit", "-yy", "-s", "256", "-e", _TRACE_EXPRESSION,
        "-o", str(trace_prefix), "--", setpriv,
        "--reuid", str(nobody.pw_uid), "--regid", str(nobody.pw_gid), "--clear-groups",
        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
        env_binary, "-i", *[f"{key}={value}" for key, value in sorted(runtime_environment.items())],
        str(runtime_binary), "--model", str(model), "--host", "127.0.0.1",
        "--port", str(port), "--ctx-size", "4096", "--threads", "2",
        "--offline", "--device", "none", "--n-gpu-layers", "0",
        "--reasoning", "off", "--parallel", "1", "--no-webui", "--no-slots",
    ]
    supervisor_started_at = _now()
    monitor_started_at = _now()
    runtime: subprocess.Popen[bytes] | None = None
    tracee_pid: int | None = None
    tracer_exit_code: int | None = None
    shutdown_traced = False
    runtime_started_at: str | None = None
    inference_started_at: str | None = None
    inference_finished_at: str | None = None
    runtime_finished_at: str | None = None
    failure: str | None = None
    run_error: Exception | None = None
    log_handle = server_log.open("wb")
    try:
        runtime = subprocess.Popen(
            runtime_command, stdin=subprocess.DEVNULL, stdout=log_handle, stderr=subprocess.STDOUT,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            close_fds=True, start_new_session=True, preexec_fn=_apply_runtime_process_limits,
        )
        tracee_pid = _capture_direct_tracee(runtime)
        runtime_started_at = _now()
        _wait_for_health(port, runtime)
        _require_tracer_running(runtime, "after loopback readiness")
        _run_trusted(
            [str(python), "-m", "second_brain_models", "no-egress-probe",
             "--runtime-port", str(port), "--isolation-id", isolation_id, "--output", str(probe)],
            environment=trusted_environment, timeout=30,
        )
        _require_tracer_running(runtime, "before inference")
        inference_started_at = _now()
        _run_trusted(
            [str(python), "-m", "second_brain_models", "infer", "--repo-root", str(root),
             "--port", str(port), "--output", str(predictions)],
            environment=trusted_environment, timeout=1_800,
        )
        inference_finished_at = _now()
        _require_tracer_running(runtime, "after inference")
    except Exception as exc:
        run_error = exc
        failure = str(exc)[:500]
    finally:
        if runtime is not None:
            try:
                if tracee_pid is None:
                    raise EvaluationError("runtime direct tracee was not captured for monitored shutdown")
                tracer_exit_code = _stop_traced_runtime(runtime, tracee_pid)
                shutdown_traced = True
            except Exception as exc:
                _emergency_stop(runtime)
                if run_error is None:
                    run_error = exc
                    failure = str(exc)[:500]
                else:
                    failure = f"{failure}; shutdown: {str(exc)[:240]}"[:500]
        runtime_finished_at = _now()
        log_handle.close()
        status = "completed" if run_error is None and inference_finished_at is not None and shutdown_traced else "failed"
        receipt = {
            "schema_version": 1,
            "status": status,
            "failure": failure,
            "isolation_id": isolation_id,
            "namespace": {"network": "new", "pid": "new", "mount": "new", "supervisor_pid": 1},
            "runtime_identity": {"user": "nobody", "uid": nobody.pw_uid, "gid": nobody.pw_gid},
            "trusted_client_identity": {"user": "root", "uid": 0, "gid": 0},
            "environment_scrubbed": True,
            "process_limits": {**_PROCESS_LIMITS, "core_bytes": 0},
            "trace_expression": _TRACE_EXPRESSION,
            "tracee_pid": tracee_pid,
            "shutdown_traced": shutdown_traced,
            "tracer_exit_code": tracer_exit_code,
            "supervisor_started_at": supervisor_started_at,
            "monitor_started_at": monitor_started_at,
            "runtime_started_at": runtime_started_at,
            "inference_started_at": inference_started_at,
            "inference_finished_at": inference_finished_at,
            "runtime_finished_at": runtime_finished_at,
        }
        write_canonical(receipt_path, receipt)
        evidence_files = [server_log, receipt_path, predictions, probe, *trace_root.glob("runtime.*")]
        for item in evidence_files:
            if not item.exists():
                continue
            if item.is_symlink() or not item.is_file():
                raise EvaluationError(f"isolated evaluator evidence path is not a regular file: {item}")
            os.chown(item, 0, artifact_reader_gid)
            item.chmod(0o640)
    if run_error is not None:
        raise EvaluationError(failure or "isolated evaluation failed") from run_error
    return receipt
