import csv
import json
import sys
import types
from io import StringIO
from types import SimpleNamespace

import pytest

from arpticuno.cli import main
from arpticuno.discovery import Host, arp_discover, validate_local_ipv4_host
from arpticuno.ports import PortResult, scan_ports_threaded, scan_tcp_ports
from arpticuno.reporting import build_payload, render_csv, render_table
from arpticuno.sandbox import build_demo_payload


def test_batch_scan_apis_enforce_private_or_link_local_ipv4_scope():
    assert validate_local_ipv4_host(" 192.168.1.10 ") == "192.168.1.10"
    assert validate_local_ipv4_host("169.254.10.20") == "169.254.10.20"

    for host in ("8.8.8.8", "example.com", "2001:db8::1", "127.0.0.1"):
        with pytest.raises(ValueError):
            scan_tcp_ports(host, [22])
        with pytest.raises(ValueError):
            scan_ports_threaded([host], [22])


def test_open_only_scan_keeps_all_probe_outcomes_for_reporting():
    observed = []

    def fake_probe(host, port, timeout):
        state = "open" if port == 22 else "timeout"
        return PortResult(host=host, port=port, state=state, latency_ms=1.0)

    results = scan_tcp_ports(
        "192.168.1.10",
        [22, 80],
        probe=fake_probe,
        workers=2,
        open_only=True,
        result_callback=observed.append,
    )

    assert [result.port for result in results] == [22]
    assert sorted(result.state for result in observed) == ["open", "timeout"]


def test_cli_reports_probe_failures_instead_of_clean_negative(capsys):
    def fake_discover(target, iface=None, timeout=1.0, retries=0):
        return [Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff")]

    def fake_probe(host, port, timeout):
        return PortResult(host=host, port=port, state="timeout", error="timeout")

    code = main(
        ["scan", "192.168.1.10", "--format", "json"],
        arp_discover=fake_discover,
        probe=fake_probe,
        ports_provider=lambda: [22, 80],
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["hosts"][0]["ports"] == []
    assert payload["hosts"][0]["probe_summary"]["total"] == 2
    assert payload["hosts"][0]["probe_summary"]["timeout"] == 2
    assert "No conclusive TCP port result" in render_table(payload)


def test_arp_discovery_rejects_malformed_data_and_marks_mac_conflicts_unknown(monkeypatch):
    class Layer:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def __truediv__(self, other):
            return self, other

    request = SimpleNamespace(sent_time=10.0)
    first = SimpleNamespace(psrc="192.168.1.10", hwsrc="AA:BB:CC:DD:EE:10", time=10.012)
    conflict = SimpleNamespace(psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:99", time=10.020)
    malformed_mac = SimpleNamespace(psrc="192.168.1.11", hwsrc="not-a-mac", time=10.020)
    outside = SimpleNamespace(psrc="8.8.8.8", hwsrc="aa:bb:cc:dd:ee:08", time=10.020)

    fake_scapy = types.ModuleType("scapy.all")
    fake_scapy.ARP = Layer
    fake_scapy.Ether = Layer
    fake_scapy.srp = lambda *args, **kwargs: (
        [(request, first), (request, conflict), (request, malformed_mac), (request, outside)],
        [],
    )
    monkeypatch.setitem(sys.modules, "scapy", types.ModuleType("scapy"))
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy)

    assert arp_discover("192.168.1.0/24") == [Host(ip="192.168.1.10", mac=None, rtt_ms=12.0)]


def test_empty_csv_contains_auditable_scan_row_and_formula_text_is_neutralized():
    empty_payload = build_payload(
        command="scan",
        inputs={"target": "192.168.1.0/24"},
        hosts=[],
        ports=[],
    )
    empty_rows = list(csv.DictReader(StringIO(render_csv(empty_payload))))
    assert len(empty_rows) == 1
    assert empty_rows[0]["scan_id"] == empty_payload["scan_id"]
    assert empty_rows[0]["status"] == "no-arp-responders"

    error_payload = build_payload(
        command="scan",
        inputs={"target": "192.168.1.10"},
        hosts=[Host(ip="192.168.1.10")],
        ports=[PortResult(host="192.168.1.10", port=22, state="error", error="=HYPERLINK(\"x\")")],
    )
    error_rows = list(csv.DictReader(StringIO(render_csv(error_payload))))
    assert error_rows[0]["error"].startswith("'=")


def test_sandbox_documents_complete_probe_counts():
    payload = build_demo_payload()
    assert sum(host["probe_summary"]["total"] for host in payload["hosts"]) == 21_000
    assert "Total TCP probes: 21000" in render_table(payload)
