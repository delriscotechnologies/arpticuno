from arpticuno.ports import PortResult, scan_tcp_ports


def test_scan_tcp_ports_is_socket_based():
    calls = []

    def fake_probe(host, port, timeout):
        calls.append((host, port, timeout))
        return PortResult(host=host, port=port, proto="tcp", state="open", latency_ms=1.2)

    results = scan_tcp_ports("192.168.1.10", [22, 443], timeout=0.75, probe=fake_probe)

    assert calls == [("192.168.1.10", 22, 0.75), ("192.168.1.10", 443, 0.75)]
    assert [result.port for result in results] == [22, 443]
    assert all(result.state == "open" for result in results)
