from __future__ import annotations

from pathlib import Path

import pytest

from second_brain_models.errors import EvaluationError
from second_brain_models.network_monitor import check_strace_logs
from second_brain_models.noegress import merge_no_egress_evidence


def test_monitor_accepts_loopback_server_without_outbound_attempts(tmp_path: Path) -> None:
    trace = tmp_path / "trace.100"
    trace.write_text(
        'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3\n'
        'bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
        'listen(3, 128) = 0\n',
        encoding="utf-8",
    )
    evidence = check_strace_logs([trace])
    assert evidence["network_attempts_observed"] == 0
    assert evidence["attempted_dns"] == 0
    assert "monitor_started_before_runtime" not in evidence


def test_trace_alone_cannot_claim_monitor_started_before_runtime(tmp_path: Path) -> None:
    trace = tmp_path / "trace.100"
    trace.write_text('socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3\nlisten(3, 128) = 0\n', encoding="utf-8")
    monitor = check_strace_logs([trace])
    probe = {
        "network_mode": "none", "dns_resolution_available": False,
        "outbound_connectivity_available": False, "default_route_present": False,
        "loopback_runtime_reachable": True, "verified_at": "2026-09-01T12:00:00Z",
        "isolation_id": "fixture-isolation-1",
    }
    with pytest.raises(EvaluationError, match="missing/unknown"):
        merge_no_egress_evidence(probe, monitor)


@pytest.mark.parametrize("line", [
    'connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16) = -1 ENETUNREACH\n',
    'sendto(4, "dns", 3, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = -1\n',
    'bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0\n',
])
def test_monitor_rejects_attempts_even_when_network_blocks_them(tmp_path: Path, line: str) -> None:
    trace = tmp_path / "trace.100"
    trace.write_text('socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3\n' + line, encoding="utf-8")
    with pytest.raises(EvaluationError, match="attempted"):
        check_strace_logs([trace])


def test_empty_trace_fails_closed(tmp_path: Path) -> None:
    trace = tmp_path / "trace.100"
    trace.write_bytes(b"")
    with pytest.raises(EvaluationError, match="no evidence"):
        check_strace_logs([trace])
