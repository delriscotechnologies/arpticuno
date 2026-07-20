from __future__ import annotations

import csv
import json
import unicodedata
from datetime import datetime, timezone
from io import StringIO
from typing import Any, cast
from uuid import uuid4

from arpticuno import __version__
from arpticuno.discovery import Host
from arpticuno.ports import PortResult

Payload = dict[str, Any]
SCHEMA_VERSION = "1.0"
PROBE_STATES = ("open", "closed", "timeout", "unreachable", "error")
FORMULA_PREFIXES = ("=", "+", "-", "@")


def build_payload(
    command: str,
    inputs: dict[str, Any],
    hosts: list[Host],
    ports: list[PortResult],
    *,
    started_at: str | None = None,
    probe_summaries: dict[str, dict[str, int]] | None = None,
) -> Payload:
    """Build the stable Arpticuno report data model."""
    ports_by_host: dict[str, list[PortResult]] = {}
    for result in ports:
        ports_by_host.setdefault(result.host, []).append(result)

    finished_at = datetime.now(timezone.utc).isoformat()
    host_payloads = [
        _host_to_dict(
            host,
            ports_by_host.get(host.ip, []),
            probe_summaries is not None,
            None if probe_summaries is None else probe_summaries.get(host.ip),
        )
        for host in hosts
    ]
    payload: Payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": "Arpticuno",
        "version": __version__,
        "scan_id": str(uuid4()),
        "command": command,
        "started_at": started_at or finished_at,
        "finished_at": finished_at,
        "inputs": inputs,
        "hosts": host_payloads,
    }
    payload["status"] = scan_status(payload)
    return payload


def _host_to_dict(
    host: Host,
    ports: list[PortResult],
    include_probe_summary: bool,
    supplied_summary: dict[str, int] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
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
    if include_probe_summary:
        payload["probe_summary"] = _normalize_probe_summary(ports, supplied_summary)
    return payload


def _normalize_probe_summary(
    ports: list[PortResult],
    supplied_summary: dict[str, int] | None,
) -> dict[str, int]:
    counts: dict[str, int] = {state: 0 for state in PROBE_STATES}
    supplied_total = 0
    if supplied_summary is None:
        for result in ports:
            state = result.state if result.state in counts else "error"
            counts[state] += 1
    else:
        for state in PROBE_STATES:
            counts[state] = max(0, int(supplied_summary.get(state, 0)))
        supplied_total = max(0, int(supplied_summary.get("total", 0)))

    observed_total = sum(counts.values())
    return {"total": max(supplied_total, observed_total), **counts}


def _summary_for_host(host: dict[str, Any]) -> dict[str, int]:
    supplied = host.get("probe_summary")
    if isinstance(supplied, dict):
        return _normalize_probe_summary([], cast(dict[str, int], supplied))

    counts: dict[str, int] = {state: 0 for state in PROBE_STATES}
    for port in host.get("ports", []):
        state = port.get("state")
        counts[state if state in counts else "error"] += 1
    return {"total": sum(counts.values()), **counts}


def scan_status(payload: Payload) -> str:
    hosts = payload.get("hosts", [])
    if not hosts:
        return "no-arp-responders"

    any_open = False
    any_failure = False
    all_failed = True
    for host in hosts:
        summary = _summary_for_host(host)
        failures = sum(summary.get(state, 0) for state in ("timeout", "unreachable", "error"))
        total = summary.get("total", 0)
        any_open = any_open or summary.get("open", 0) > 0
        any_failure = any_failure or failures > 0
        all_failed = all_failed and total > 0 and failures == total

    if all_failed:
        return "inconclusive"
    if any_failure:
        return "partial"
    if any_open:
        return "completed"
    return "no-open-ports"


def is_inconclusive(payload: Payload) -> bool:
    return scan_status(payload) == "inconclusive"


def render_json(payload: Payload) -> str:
    return json.dumps(payload, indent=2, allow_nan=False)


def render_table(payload: Payload) -> str:
    target = payload.get("inputs", {}).get("target") or payload.get("inputs", {}).get("cidr", "")
    hosts = payload.get("hosts", [])
    open_port_count = sum(
        1 for host in hosts for port in host.get("ports", []) if port.get("state") == "open"
    )
    total_probes = sum(_summary_for_host(host).get("total", 0) for host in hosts)
    summary = (
        f"Results:  Target(s): {target or '-'}  │  "
        f"Total ARP responders: {len(hosts)}  │  "
        f"Total TCP probes: {total_probes}  │  "
        f"Total open TCP ports: {open_port_count}"
    )
    lines = [summary, f"Status: {scan_status(payload)}", "", "ARP responders:"]
    if not hosts:
        lines.append("  No ARP responders found.")
        return "\n".join(lines) + "\n"

    for index, host in enumerate(hosts, start=1):
        open_ports = [port for port in host.get("ports", []) if port.get("state") == "open"]
        probe_summary = _summary_for_host(host)
        failed_probes = sum(
            probe_summary.get(state, 0) for state in ("timeout", "unreachable", "error")
        )
        total_host_probes = probe_summary.get("total", 0)
        lines.extend(
            [
                f"  Host {index}",
                f"    IPv4: {host['ip']}",
                f"    MAC: {host.get('mac') or 'unknown'}",
                f"    ARP RTT: {_display(host.get('arp_rtt_ms'))} ms",
                f"    TCP Probes: {total_host_probes}",
                f"    Open TCP Ports: {len(open_ports)}",
            ]
        )
        if failed_probes:
            lines.append(
                f"    Probe Warning: {failed_probes} probes timed out, were unreachable, or failed."
            )
        if open_ports:
            for port in open_ports:
                latency = _display(port.get("latency_ms"), empty="-")
                lines.append(
                    f"      Port: {port['port']}/{port['proto']} | "
                    f"State: {port['state']} | Latency: {latency} ms"
                )
        elif total_host_probes and failed_probes == total_host_probes:
            lines.append("      No conclusive TCP port result was obtained for this host.")
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
        "started_at",
        "finished_at",
        "record_type",
        "status",
        "total_probes",
        "open_count",
        "closed_count",
        "timeout_count",
        "unreachable_count",
        "error_count",
        "schema_version",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()

    target = payload.get("inputs", {}).get("target") or payload.get("inputs", {}).get("cidr", "")
    hosts = payload.get("hosts", [])
    if not hosts:
        writer.writerow(_sanitize_csv_row(_scan_row(payload, target)))
        return buffer.getvalue()

    for host in hosts:
        if not host.get("ports"):
            writer.writerow(_sanitize_csv_row(_row(payload, target, host, None)))
            continue
        for port in host["ports"]:
            writer.writerow(_sanitize_csv_row(_row(payload, target, host, port)))
    return buffer.getvalue()


def _scan_row(payload: Payload, target: str) -> dict[str, Any]:
    return {
        "schema_version": payload.get("schema_version", SCHEMA_VERSION),
        "scan_id": payload["scan_id"],
        "command": payload["command"],
        "target": target,
        "started_at": payload.get("started_at", ""),
        "finished_at": payload.get("finished_at", ""),
        "record_type": "scan",
        "status": scan_status(payload),
    }


def _row(
    payload: Payload,
    target: str,
    host: dict[str, Any],
    port: dict[str, Any] | None,
) -> dict[str, Any]:
    summary = _summary_for_host(host)
    failed = sum(summary.get(state, 0) for state in ("timeout", "unreachable", "error"))
    total = summary.get("total", 0)
    if failed == total and total:
        status = "probe-failure"
    elif failed:
        status = "partial-probe-failure"
    elif summary.get("open", 0):
        status = "completed"
    elif total:
        status = "no-open-ports"
    else:
        status = "not-scanned"

    return {
        "schema_version": payload.get("schema_version", SCHEMA_VERSION),
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
        "started_at": payload.get("started_at", ""),
        "finished_at": payload.get("finished_at", ""),
        "record_type": "host" if port is None else "port",
        "status": status,
        "total_probes": total,
        "open_count": summary.get("open", 0),
        "closed_count": summary.get("closed", 0),
        "timeout_count": summary.get("timeout", 0),
        "unreachable_count": summary.get("unreachable", 0),
        "error_count": summary.get("error", 0),
    }


def _sanitize_csv_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: _csv_safe(value) for key, value in row.items()}


def _csv_safe(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value

    first_visible = 0
    leading_control = False
    while first_visible < len(value):
        character = value[first_visible]
        is_control = unicodedata.category(character).startswith("C")
        if not character.isspace() and not is_control:
            break
        leading_control = leading_control or is_control
        first_visible += 1

    if leading_control or value[first_visible:].startswith(FORMULA_PREFIXES):
        return f"'{value}"
    return value


def _display(value: Any, empty: str = "-") -> str:
    return empty if value is None else str(value)


# Backwards-compatible helper for older callers/tests.
def build_report(
    target: str,
    hosts: list[Host],
    results_by_host: dict[str, list[PortResult]],
) -> Payload:
    ports = [result for results in results_by_host.values() for result in results]
    return build_payload(command="scan", inputs={"target": target}, hosts=hosts, ports=ports)
