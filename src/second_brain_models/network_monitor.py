"""Fail-closed parsing of trusted runtime network-syscall traces."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from .errors import EvaluationError


_NETWORK_ATTEMPT = re.compile(r"\b(?:connect|sendto|sendmsg)\([^\n]*(?:AF_INET|AF_INET6)")
_WILDCARD_BIND = re.compile(r"\bbind\([^\n]*(?:0\.0\.0\.0|\"::\"|in6addr_any)")
_NETWORK_SOCKET = re.compile(r"\bsocket\((?:AF_INET|AF_INET6),")


def check_strace_logs(paths: list[Path]) -> dict[str, Any]:
    if not paths:
        raise EvaluationError("network monitoring produced no trace files")
    digest = hashlib.sha256()
    attempts: list[str] = []
    saw_network_monitoring = False
    total_bytes = 0
    for path in sorted(paths, key=lambda item: item.as_posix()):
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8", errors="replace")
        except OSError as exc:
            raise EvaluationError(f"could not read network trace {path}: {exc}") from exc
        total_bytes += len(raw)
        digest.update(path.name.encode("utf-8") + b"\0" + raw)
        saw_network_monitoring = saw_network_monitoring or bool(_NETWORK_SOCKET.search(text) or "bind(" in text or "listen(" in text)
        for line in text.splitlines():
            if _NETWORK_ATTEMPT.search(line) or _WILDCARD_BIND.search(line):
                attempts.append(f"{path.name}:{line[:300]}")
    if total_bytes == 0 or not saw_network_monitoring:
        raise EvaluationError("network trace contains no evidence that runtime networking syscalls were monitored")
    if attempts:
        raise EvaluationError(f"runtime attempted network access or non-loopback binding ({len(attempts)} observed)")
    return {
        "monitor_method": "strace-network-syscalls",
        "network_attempts_observed": 0,
        "attempted_dns": 0,
        "attempted_tcp": 0,
        "attempted_udp": 0,
        "monitor_evidence_sha256": digest.hexdigest(),
    }
