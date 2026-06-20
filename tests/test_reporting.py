import math

import pytest

from arpticuno.discovery import Host
from arpticuno.ports import PortResult
from arpticuno.reporting import build_payload, render_csv, render_json, render_table


def test_build_payload_uses_simple_command_schema():
    payload = build_payload(
        command="scan",
        inputs={"target": "192.168.1.0/24", "port_range": "1-7000"},
        hosts=[Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", rtt_ms=2.4)],
        ports=[PortResult(host="192.168.1.10", port=22, proto="tcp", state="open", latency_ms=3.1)],
    )

    assert payload["tool"] == "Arpticuno"
    assert payload["command"] == "scan"
    assert payload["inputs"]["target"] == "192.168.1.0/24"
    assert payload["hosts"] == [
        {
            "ip": "192.168.1.10",
            "mac": "aa:bb:cc:dd:ee:ff",
            "arp_rtt_ms": 2.4,
            "ports": [
                {"port": 22, "proto": "tcp", "state": "open", "latency_ms": 3.1, "error": None}
            ],
        }
    ]


def test_renderers_are_plain_and_beginner_friendly():
    payload = build_payload(
        command="scan",
        inputs={"target": "127.0.0.1", "port_range": "1-7000"},
        hosts=[Host(ip="127.0.0.1")],
        ports=[PortResult(host="127.0.0.1", port=22, proto="tcp", state="closed", latency_ms=0.5)],
    )

    table = render_table(payload)
    assert '"command": "scan"' in render_json(payload)
    assert "Results:  Target(s): 127.0.0.1" in table
    assert "│  Total active hosts: 1" in table
    assert "│  Total open TCP ports: 0" in table
    assert "Active hosts:" in table
    assert "IPv4: 127.0.0.1" in table
    assert "MAC: unknown" in table
    assert "No open TCP ports found on this host." in table
    assert "scan_id,command,target,host_ip" in render_csv(payload)
    assert ",22,tcp,closed,0.5," in render_csv(payload)


def test_render_json_rejects_non_standard_nan_values():
    payload = build_payload(command="scan", inputs={"target": "192.168.1.10", "arp_timeout": math.nan}, hosts=[], ports=[])

    with pytest.raises(ValueError):
        render_json(payload)
