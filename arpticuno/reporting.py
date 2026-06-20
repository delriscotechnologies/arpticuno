from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from io import StringIO
from typing import Any
from uuid import uuid4

from arpticuno import __version__
from arpticuno.discovery import Host
from arpticuno.ports import PortResult


Payload = dict[str, Any]


def build_payload(command: str, inputs: dict[str, Any], hosts: list[Host], ports: list[PortResult]) -> Payload:
    """Build the simple ARPTICUNO JSON/CSV/table data model."""
    ports_by_host: dict[str, list[PortResult]] = {}
    for result in ports:
        ports_by_host.setdefault(result.host, []).append(result)

    return {
        "tool": "Arpticuno",
        "version": __version__,
        "scan_id": str(uuid4()),
        "command": command,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "inputs": inputs,
        "hosts": [_host_to_dict(host, ports_by_host.get(host.ip, [])) for host in hosts],
    }


def _host_to_dict(host: Host, ports: list[PortResult]) -> dict[str, Any]:
    return {
        "ip": host.ip,
        "mac": host.mac,
        "arp_rtt_ms": host.rtt_ms,
        "ports": [
            {
                "port": result.port,
                "proto": result.proto,
                "state": result.state,
                "latency_ms": result.latency_ms,
                "error": result.error,
            }
            for result in ports
        ],
    }


def render_json(payload: Payload) -> str:
    return json.dumps(payload, indent=2, allow_nan=False)


def render_table(payload: Payload) -> str:
    target = payload.get("inputs", {}).get("target") or payload.get("inputs", {}).get("cidr", "")
    hosts = payload.get("hosts", [])
    open_port_count = sum(
        1 for host in hosts for port in host.get("ports", []) if port.get("state") == "open"
    )

    summary = (
        f"Results:  Target(s): {target or '-'}  │  "
        f"Total active hosts: {len(hosts)}  │  "
        f"Total open TCP ports: {open_port_count}"
    )
    lines = [
        summary,
        "",
        "Active hosts:",
    ]

    if not hosts:
        lines.append("  No active hosts found.")
        return "\n".join(lines) + "\n"

    for index, host in enumerate(hosts, start=1):
        open_ports = [port for port in host.get("ports", []) if port.get("state") == "open"]
        lines.extend(
            [
                f"  Host {index}",
                f"    IPv4: {host['ip']}",
                f"    MAC: {host.get('mac') or 'unknown'}",
                f"    ARP RTT: {_display(host.get('arp_rtt_ms'))} ms",
                f"    Open TCP Ports: {len(open_ports)}",
            ]
        )

        if open_ports:
            for port in open_ports:
                latency = _display(port.get("latency_ms"), empty="-")
                lines.append(
                    f"      Port: {port['port']}/{port['proto']} | State: {port['state']} | Latency: {latency} ms"
                )
        else:
            lines.append("      No open TCP ports found on this host.")

        if index != len(hosts):
            lines.append("")

    return "\n".join(lines) + "\n"


def render_csv(payload: Payload) -> str:
    buffer = StringIO()
    fieldnames = [
        "scan_id",
        "command",
        "target",
        "host_ip",
        "host_mac",
        "arp_rtt_ms",
        "port",
        "proto",
        "state",
        "latency_ms",
        "error",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()

    target = payload.get("inputs", {}).get("target") or payload.get("inputs", {}).get("cidr", "")
    for host in payload["hosts"]:
        if not host.get("ports"):
            writer.writerow(_row(payload, target, host, None))
            continue
        for port in host["ports"]:
            writer.writerow(_row(payload, target, host, port))

    return buffer.getvalue()


def _row(payload: Payload, target: str, host: dict[str, Any], port: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "scan_id": payload["scan_id"],
        "command": payload["command"],
        "target": target,
        "host_ip": host["ip"],
        "host_mac": host.get("mac") or "",
        "arp_rtt_ms": _display(host.get("arp_rtt_ms"), empty=""),
        "port": "" if port is None else port["port"],
        "proto": "" if port is None else port["proto"],
        "state": "" if port is None else port["state"],
        "latency_ms": "" if port is None else _display(port.get("latency_ms"), empty=""),
        "error": "" if port is None else port.get("error") or "",
    }


def _display(value: Any, empty: str = "-") -> str:
    return empty if value is None else str(value)


# Backwards-compatible helper for older callers/tests.
def build_report(target: str, hosts: list[Host], results_by_host: dict[str, list[PortResult]]) -> Payload:
    ports = [result for results in results_by_host.values() for result in results]
    return build_payload(command="scan", inputs={"target": target}, hosts=hosts, ports=ports)
