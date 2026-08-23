from contextlib import nullcontext

import pytest

from arpticuno import ports


def test_parse_ports_deduplicates_and_sorts() -> None:
    assert ports.parse_ports("443,80,80,100-102") == [80, 100, 101, 102, 443]


@pytest.mark.parametrize("value", ["", "0", "65536", "80-70", "80--81", "80,"])
def test_parse_ports_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError):
        ports.parse_ports(value)


def test_probe_connect_classifies_socket_results(monkeypatch) -> None:
    monkeypatch.setattr(ports.socket, "create_connection", lambda *args, **kwargs: nullcontext())
    assert ports.probe_connect("192.168.1.1", 80).state == "open"

    def refused(*args, **kwargs):
        raise ConnectionRefusedError(10061, "refused")

    monkeypatch.setattr(ports.socket, "create_connection", refused)
    assert ports.probe_connect("192.168.1.1", 80).state == "closed"

    def timed_out(*args, **kwargs):
        raise TimeoutError

    monkeypatch.setattr(ports.socket, "create_connection", timed_out)
    assert ports.probe_connect("192.168.1.1", 80).state == "timeout"


def test_shared_scanner_preserves_order_and_reports_every_result() -> None:
    observed: list[ports.PortResult] = []
    progress: list[tuple[int, int]] = []

    def probe(host: str, port: int, timeout: float) -> ports.PortResult:
        state = "open" if port == 80 else "closed"
        return ports.PortResult(host, port, state)

    results = ports.scan_ports_threaded(
        ["192.168.1.2", "192.168.1.1"],
        [443, 80],
        workers=2,
        probe=probe,
        open_only=True,
        result_callback=observed.append,
        progress=lambda done, total: progress.append((done, total)),
    )

    assert [(result.host, result.port) for result in results] == [
        ("192.168.1.2", 80),
        ("192.168.1.1", 80),
    ]
    assert len(observed) == 4
    assert progress[-1] == (4, 4)


def test_single_host_scanner_uses_shared_engine() -> None:
    def probe(host: str, port: int, timeout: float) -> ports.PortResult:
        return ports.PortResult(host, port, "open")

    assert ports.scan_tcp_ports("192.168.1.1", [22, 80], workers=1, probe=probe) == [
        ports.PortResult("192.168.1.1", 22, "open"),
        ports.PortResult("192.168.1.1", 80, "open"),
    ]


def test_scanner_rejects_public_hosts_before_running_probe() -> None:
    called = False

    def probe(host: str, port: int, timeout: float) -> ports.PortResult:
        nonlocal called
        called = True
        return ports.PortResult(host, port, "open")

    with pytest.raises(ValueError):
        ports.scan_ports_threaded(["8.8.8.8"], [53], probe=probe)
    assert not called
