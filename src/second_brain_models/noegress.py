"""Produce fail-closed evidence that an evaluation runner has no egress."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import re
from typing import Any

from .errors import EvaluationError


def _interfaces() -> list[str]:
    try:
        return sorted(name for _, name in socket.if_nameindex())
    except OSError:
        return []


def _has_default_route() -> bool:
    route_file = Path("/proc/net/route")
    if not route_file.is_file():
        # Unknown is unsafe. Windows/macOS evaluation is intentionally not a
        # supported publisher runner in v1.
        return True
    try:
        rows = route_file.read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        return True
    for row in rows:
        fields = row.split()
        if len(fields) >= 4 and fields[1] == "00000000" and fields[0] != "lo":
            return True
    return False


def _dns_is_blocked() -> bool:
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(0.5)
    try:
        try:
            socket.getaddrinfo("example.com", 443, type=socket.SOCK_STREAM)
            return False
        except OSError:
            return True
    finally:
        socket.setdefaulttimeout(previous_timeout)


def _outbound_socket_is_blocked() -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        return sock.connect_ex(("1.1.1.1", 443)) != 0
    finally:
        sock.close()


def _loopback_reachable(port: int) -> bool:
    if not 1 <= port <= 65535:
        raise EvaluationError("runtime port must be between 1 and 65535")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        return sock.connect_ex(("127.0.0.1", port)) == 0
    finally:
        sock.close()


def probe_no_egress(*, runtime_port: int, isolation_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,159}", isolation_id):
        raise EvaluationError("isolation_id must be a safe opaque identifier")
    interfaces = _interfaces()
    checks = {
        "declared_network_none": os.environ.get("SB_MODELS_NETWORK_MODE") == "none",
        "loopback_only": bool(interfaces) and set(interfaces) <= {"lo"},
        "no_default_route": not _has_default_route(),
        "dns_resolution_blocked": _dns_is_blocked(),
        "outbound_socket_blocked": _outbound_socket_is_blocked(),
        "loopback_runtime_reachable": _loopback_reachable(runtime_port),
    }
    evidence: dict[str, Any] = {
        "network_mode": "none",
        "dns_resolution_available": not checks["dns_resolution_blocked"],
        "outbound_connectivity_available": not checks["outbound_socket_blocked"],
        "default_route_present": not checks["no_default_route"],
        "loopback_runtime_reachable": checks["loopback_runtime_reachable"],
        "verified_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "isolation_id": isolation_id,
    }
    if not all(checks.values()):
        failed = sorted(name for name, passed in checks.items() if not passed)
        raise EvaluationError(f"no-egress evidence failed closed: {', '.join(failed)}")
    return evidence


def merge_no_egress_evidence(probe: dict[str, Any], monitor: dict[str, Any]) -> dict[str, Any]:
    expected_probe = {
        "network_mode", "dns_resolution_available", "outbound_connectivity_available",
        "default_route_present", "loopback_runtime_reachable", "verified_at", "isolation_id",
    }
    expected_monitor = {
        "monitor_method", "monitor_started_before_runtime", "attempted_dns", "attempted_tcp",
        "attempted_udp", "network_attempts_observed", "monitor_evidence_sha256",
    }
    if set(probe) != expected_probe or set(monitor) != expected_monitor:
        raise EvaluationError("isolation probe or network-monitor receipt has missing/unknown fields")
    evidence = {**probe, **monitor}
    if (
        evidence["network_mode"] != "none" or evidence["dns_resolution_available"] is not False
        or evidence["outbound_connectivity_available"] is not False
        or evidence["default_route_present"] is not False
        or evidence["loopback_runtime_reachable"] is not True
        or evidence["monitor_started_before_runtime"] is not True
        or any(evidence[key] != 0 for key in ("attempted_dns", "attempted_tcp", "attempted_udp", "network_attempts_observed"))
    ):
        raise EvaluationError("isolation evidence does not prove a monitored local-only evaluation")
    return evidence


def collect_no_egress_evidence(*, runtime_port: int, isolation_id: str, monitor_evidence: dict[str, Any]) -> dict[str, Any]:
    return merge_no_egress_evidence(
        probe_no_egress(runtime_port=runtime_port, isolation_id=isolation_id), monitor_evidence,
    )
