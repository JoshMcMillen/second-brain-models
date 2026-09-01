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
    'connect(3, {sa_family=AF_UNIX, sun_path="/run/host.sock"}, 110) = -1 ENOENT\n',
    'sendto(4, "dns", 3, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, 16) = -1\n',
    'bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0\n',
    'bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("10.0.0.2")}, 16) = -1 EADDRNOTAVAIL\n',
    'socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3\n',
    'socket(AF_VSOCK, SOCK_STREAM, 0) = -1 EPERM\n',
    'socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) = -1 EPERM\n',
    'socket(AF_INET, SOCK_RAW, IPPROTO_RAW) = -1 EPERM\n',
    'socketpair(AF_UNIX, SOCK_STREAM, 0, [3, 4]) = 0\n',
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


def test_connected_stream_writes_with_null_destination_are_not_false_egress(tmp_path: Path) -> None:
    trace = tmp_path / "trace.100"
    trace.write_text(
        'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3\n'
        'bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
        'sendto(4, "ok", 2, MSG_NOSIGNAL, NULL, 0) = 2\n'
        'sendmsg(4, {msg_name=NULL, msg_namelen=0, msg_iov=[]}, MSG_NOSIGNAL) = 2\n'
        'sendmmsg(4, [{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[]}, msg_len=2}], 1, 0) = 1\n',
        encoding="utf-8",
    )
    assert check_strace_logs([trace])["network_attempts_observed"] == 0


def test_successful_exact_runtime_exec_proves_monitor_started_first(tmp_path: Path) -> None:
    trace = tmp_path / "trace.100"
    trace.write_text(
        'execve("/tmp/llama-server", ["/tmp/llama-server"], 0x1234) = 0\n'
        'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3\n'
        'bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n',
        encoding="utf-8",
    )
    evidence = check_strace_logs([trace], expected_runtime_executable=Path("/tmp/llama-server"))
    assert evidence["monitor_started_before_runtime"] is True


def test_missing_exact_runtime_exec_cannot_claim_start_order(tmp_path: Path) -> None:
    trace = tmp_path / "trace.100"
    trace.write_text(
        'execve("/tmp/not-llama", ["/tmp/not-llama"], 0x1234) = 0\n'
        'socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3\n',
        encoding="utf-8",
    )
    with pytest.raises(EvaluationError, match="exact runtime executable"):
        check_strace_logs([trace], expected_runtime_executable=Path("/tmp/llama-server"))


@pytest.mark.parametrize("line", [
    'sendmmsg(3, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53)}}}], 1, 0) = -1 EPERM\n',
    'io_uring_setup(8, {flags=0}) = 4\n',
    'clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = 12\n',
])
def test_sendmmsg_and_io_uring_blind_spots_fail_closed(tmp_path: Path, line: str) -> None:
    trace = tmp_path / "trace.100"
    trace.write_text('socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 3\n' + line, encoding="utf-8")
    with pytest.raises(EvaluationError):
        check_strace_logs([trace])
