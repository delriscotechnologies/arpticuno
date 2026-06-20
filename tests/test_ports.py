import math
import socket

import pytest

from arpticuno.ports import PortResult, parse_ports, probe_connect, scan_ports_threaded, scan_tcp_ports


def test_parse_ports_supports_comma_ranges_and_dedupes():
    assert parse_ports("22,80,80,1000-1002") == [22, 80, 1000, 1001, 1002]


@pytest.mark.parametrize("value", ["", "0", "65536", "1-1000000000", "100-90", "abc"])
def test_parse_ports_rejects_invalid_input(value):
    with pytest.raises(ValueError):
        parse_ports(value)


def test_probe_connect_detects_open_local_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    host, port = server.getsockname()

    try:
        result = probe_connect(host, port, timeout=0.5)
    finally:
        server.close()

    assert result == PortResult(
        host=host,
        port=port,
        state="open",
        proto="tcp",
        latency_ms=result.latency_ms,
        error=None,
    )
    assert result.latency_ms is not None
    assert result.latency_ms >= 0


def test_scan_tcp_ports_uses_probe_for_one_host():
    calls = []

    def fake_probe(host, port, timeout):
        calls.append((host, port, timeout))
        return PortResult(host=host, port=port, proto="tcp", state="closed", latency_ms=1.0)

    results = scan_tcp_ports("192.168.1.10", [22, 80], timeout=0.25, probe=fake_probe, workers=2)

    assert calls == [("192.168.1.10", 22, 0.25), ("192.168.1.10", 80, 0.25)]
    assert [result.port for result in results] == [22, 80]
    assert all(result.state == "closed" for result in results)


def test_scan_tcp_ports_can_return_only_open_ports():
    def fake_probe(host, port, timeout):
        state = "open" if port == 22 else "closed"
        return PortResult(host=host, port=port, proto="tcp", state=state, latency_ms=1.0)

    results = scan_tcp_ports("192.168.1.10", [22, 80], timeout=0.25, probe=fake_probe, workers=2, open_only=True)

    assert [result.port for result in results] == [22]


def test_scan_tcp_ports_rejects_unsafe_worker_count():
    with pytest.raises(ValueError):
        scan_tcp_ports("192.168.1.10", [22], timeout=0.25, workers=9999)


def test_scan_tcp_ports_rejects_non_finite_timeout():
    with pytest.raises(ValueError):
        scan_tcp_ports("192.168.1.10", [22], timeout=math.nan)


def test_scan_ports_threaded_scans_each_host():
    calls = []

    def fake_probe(host, port, timeout):
        calls.append((host, port, timeout))
        return PortResult(host=host, port=port, proto="tcp", state="closed", latency_ms=1.0)

    results = scan_ports_threaded(["192.168.1.10", "192.168.1.20"], [22], timeout=0.25, workers=2, probe=fake_probe)

    assert calls == [("192.168.1.10", 22, 0.25), ("192.168.1.20", 22, 0.25)]
    assert len(results) == 2



def test_scan_ports_threaded_reports_progress():
    progress_updates = []

    def fake_probe(host, port, timeout):
        return PortResult(host=host, port=port, proto="tcp", state="closed", latency_ms=1.0)

    scan_ports_threaded(
        ["192.168.1.10", "192.168.1.20"],
        [22, 80],
        timeout=0.25,
        workers=2,
        probe=fake_probe,
        progress=lambda done, total: progress_updates.append((done, total)),
    )

    assert progress_updates
    assert progress_updates[-1] == (4, 4)
