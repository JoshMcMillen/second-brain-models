"""Fail-closed parsing of trusted runtime network-syscall traces."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
from typing import Any

from .errors import EvaluationError


_CONNECT = re.compile(r"\bconnect\(")
_SEND = re.compile(r"\b(sendto|sendmsg|sendmmsg)\(")
_SOCKET = re.compile(r"\bsocket\(([^,\s]+),\s*([^,\n]+),")
_SOCKETPAIR = re.compile(r"\bsocketpair\(")
_IP_BIND = re.compile(r"\bbind\([^\n]*(AF_INET6|AF_INET)")
_NETWORK_SOCKET = re.compile(r"\bsocket\((?:AF_INET|AF_INET6),")
_SUCCESSFUL_EXEC = re.compile(r'\bexecve\("([^"\\]*(?:\\.[^"\\]*)*)"[^\n]*\)\s+=\s+0\b')
_PROCESS_CREATION = re.compile(r"\b(?:clone|clone3|fork|vfork)\(")
_IO_URING = re.compile(r"\bio_uring_(?:setup|enter|register)\(")
_UNTRACED_CLONE = re.compile(r"\bCLONE_UNTRACED\b")
_MAX_TRACE_FILES = 1_024
_MAX_TRACE_BYTES = 16 * 1024 * 1024


def _send_has_no_destination(line: str, operation: str) -> bool:
    if operation == "sendto":
        return bool(re.search(r",\s*NULL,\s*0\)\s+=", line))
    names = re.findall(r"msg_name=([^,}\]]+)", line)
    return bool(names) and all(name.strip() == "NULL" for name in names)


def _line_attempts_external_ipc(line: str) -> bool:
    if _CONNECT.search(line) or _SOCKETPAIR.search(line):
        return True
    socket_call = _SOCKET.search(line)
    if socket_call:
        family, socket_type = socket_call.groups()
        if family not in {"AF_INET", "AF_INET6"}:
            return True
        if "SOCK_STREAM" not in socket_type or any(
            forbidden in socket_type for forbidden in ("SOCK_DGRAM", "SOCK_RAW", "SOCK_SEQPACKET")
        ):
            return True
    bind_call = _IP_BIND.search(line)
    if "bind(" in line and not bind_call:
        return True
    if bind_call:
        family = bind_call.group(1)
        if family == "AF_INET" and 'inet_addr("127.0.0.1")' not in line:
            return True
        if family == "AF_INET6" and '"::1"' not in line:
            return True
    send_call = _SEND.search(line)
    if send_call and not _send_has_no_destination(line, send_call.group(1)):
        return True
    return False


def check_strace_logs(
    paths: list[Path], *, expected_runtime_executable: Path | None = None,
) -> dict[str, Any]:
    if not paths:
        raise EvaluationError("network monitoring produced no trace files")
    if len(paths) > _MAX_TRACE_FILES:
        raise EvaluationError("network monitoring produced too many trace files")
    digest = hashlib.sha256()
    attempts: list[str] = []
    total_bytes = 0
    expected_exec = os.path.realpath(expected_runtime_executable) if expected_runtime_executable else None
    records: list[tuple[Path, bytes, str]] = []
    for path in sorted(paths, key=lambda item: item.as_posix()):
        try:
            size = path.stat().st_size
            if size > _MAX_TRACE_BYTES - total_bytes:
                raise EvaluationError("network trace exceeds the bounded evidence size")
            raw = path.read_bytes()
            text = raw.decode("utf-8", errors="replace")
        except OSError as exc:
            raise EvaluationError(f"could not read network trace {path}: {exc}") from exc
        total_bytes += len(raw)
        digest.update(path.name.encode("utf-8") + b"\0" + raw)
        records.append((path, raw, text))

    runtime_boundary: tuple[Path, int] | None = None
    if expected_exec is not None:
        boundaries: list[tuple[Path, int]] = []
        for path, _, text in records:
            for match in _SUCCESSFUL_EXEC.finditer(text):
                # Evaluator paths are constrained to safe ASCII archive members;
                # reject escaped strace paths instead of trying to interpret them.
                traced_path = match.group(1)
                if "\\" not in traced_path and os.path.realpath(traced_path) == expected_exec:
                    boundaries.append((path, match.end()))
        if len(boundaries) != 1:
            raise EvaluationError("network trace does not show exactly one launch of the exact runtime executable")
        runtime_boundary = boundaries[0]
        boundary_text = next(text for path, _, text in records if path == runtime_boundary[0])
        if _PROCESS_CREATION.search(boundary_text[:runtime_boundary[1]]):
            raise EvaluationError("trusted runtime wrapper created a process before the exact runtime launch")

    saw_network_monitoring = False
    for path, _, text in records:
        monitored_text = text
        if runtime_boundary is not None and path == runtime_boundary[0]:
            monitored_text = text[runtime_boundary[1]:]
        saw_network_monitoring = saw_network_monitoring or bool(
            _NETWORK_SOCKET.search(monitored_text) or "bind(" in monitored_text or "listen(" in monitored_text
        )
        if _IO_URING.search(monitored_text):
            raise EvaluationError("runtime used io_uring, which is outside the v1 syscall monitor boundary")
        if _UNTRACED_CLONE.search(monitored_text):
            raise EvaluationError("runtime requested CLONE_UNTRACED, which would escape process-tree monitoring")
        for line in monitored_text.splitlines():
            if _line_attempts_external_ipc(line):
                attempts.append(f"{path.name}:{line[:300]}")
    if attempts:
        raise EvaluationError(f"runtime attempted network access or non-loopback binding ({len(attempts)} observed)")
    if total_bytes == 0 or not saw_network_monitoring:
        raise EvaluationError("network trace contains no evidence that runtime networking syscalls were monitored")
    evidence = {
        "monitor_method": "strace-network-syscalls",
        "network_attempts_observed": 0,
        "attempted_dns": 0,
        "attempted_tcp": 0,
        "attempted_udp": 0,
        "monitor_evidence_sha256": digest.hexdigest(),
    }
    if expected_exec is not None:
        # A successful execve recorded by the tracer can only occur after the
        # tracer attached and before the runtime made subsequent syscalls.
        evidence["monitor_started_before_runtime"] = True
    return evidence
