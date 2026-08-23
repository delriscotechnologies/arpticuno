from __future__ import annotations

import csv
import json
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Mapping
from datetime import datetime, timezone
from io import StringIO
from typing import Any
from uuid import uuid4

from arpticuno import __version__
from arpticuno.discovery import Host
from arpticuno.ports import PortResult

Payload = dict[str, Any]
SCHEMA_VERSION = "1.0"
PROBE_STATES = ("open", "closed", "timeout", "unreachable", "error")
FAILURE_STATES = ("timeout", "unreachable", "error")
FORMULA_PREFIXES = ("=", "+", "-", "@")
PORT_FIELDS = ("port", "proto", "state", "latency_ms", "error")
CSV_FIELDS = [
    "scan_id", "command", "target", "host_ip", "host_mac", "arp_rtt_ms", "port", "proto",
    "state", "latency_ms", "error", "started_at", "finished_at", "record_type", "status",
    "total_probes", "open_count", "closed_count", "timeout_count", "unreachable_count",
    "error_count", "schema_version",
]


def build_payload(
    command: str,
    inputs: dict[str, Any],
    hosts: list[Host],
    ports: list[PortResult],
    *,
    started_at: str | None = None,
    probe_summaries: dict[str, dict[str, int]] | None = None,
) -> Payload:
    """Build the stable report shared by every renderer."""
    grouped: defaultdict[str, list[PortResult]] = defaultdict(list)
    for result in ports:
        grouped[result.host].append(result)
    finished_at = datetime.now(timezone.utc).isoformat()
    payload: Payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": "Arpticuno",
        "version": __version__,
        "scan_id": str(uuid4()),
        "command": command,
        "started_at": started_at or finished_at,
        "finished_at": finished_at,
        "inputs": inputs,
        "hosts": [_host_payload(host, grouped[host.ip], probe_summaries) for host in hosts],
    }
    payload["status"] = scan_status(payload)
    return payload


def _host_payload(
    host: Host, results: list[PortResult], summaries: dict[str, dict[str, int]] | None
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ip": host.ip,
        "mac": host.mac,
        "arp_rtt_ms": host.rtt_ms,
        "ports": [{field: getattr(result, field) for field in PORT_FIELDS} for result in results],
    }
    if summaries is not None:
        if host.ip in summaries:
            payload["probe_summary"] = summaries[host.ip]
        payload["probe_summary"] = _summary(payload)
    return payload


def _summary(host: dict[str, Any]) -> dict[str, int]:
    supplied = host.get("probe_summary")
    if isinstance(supplied, Mapping):
        counts = Counter({state: max(0, int(supplied.get(state, 0))) for state in PROBE_STATES})
        reported_total = max(0, int(supplied.get("total", 0)))
    else:
        states = (port.get("state") for port in host.get("ports", []))
        counts = Counter(state if state in PROBE_STATES else "error" for state in states)
        reported_total = 0
    normalized = {state: counts[state] for state in PROBE_STATES}
    return {"total": max(reported_total, sum(normalized.values())), **normalized}


def _failure_count(summary: Mapping[str, int]) -> int:
    return sum(summary.get(state, 0) for state in FAILURE_STATES)


def scan_status(payload: Payload) -> str:
    hosts = payload.get("hosts", [])
    if not hosts:
        return "no-arp-responders"
    summaries = [_summary(host) for host in hosts]
    if all(summary["total"] and _failure_count(summary) == summary["total"] for summary in summaries):
        return "inconclusive"
    if any(_failure_count(summary) for summary in summaries):
        return "partial"
    return "completed" if any(summary["open"] for summary in summaries) else "no-open-ports"


def is_inconclusive(payload: Payload) -> bool:
    return scan_status(payload) == "inconclusive"


def render_json(payload: Payload) -> str:
    return json.dumps(payload, indent=2, allow_nan=False)


def render_table(payload: Payload) -> str:
    hosts = payload.get("hosts", [])
    target = str(payload.get("inputs", {}).get("target", ""))
    total_probes = sum(_summary(host)["total"] for host in hosts)
    open_count = sum(port.get("state") == "open" for host in hosts for port in host.get("ports", []))
    lines = [
        (
            f"Results: Target(s): {target or '-'} | ARP responders: {len(hosts)} | "
            f"TCP probes: {total_probes} | Open TCP ports: {open_count}"
        ),
        f"Status: {scan_status(payload)}",
        "",
        "ARP responders:",
    ]
    if not hosts:
        lines.append("  No ARP responders found.")
    for index, host in enumerate(hosts, 1):
        if index > 1:
            lines.append("")
        lines.extend(_host_lines(index, host))
    return "\n".join(lines) + "\n"


def _host_lines(index: int, host: dict[str, Any]) -> list[str]:
    summary = _summary(host)
    failures = _failure_count(summary)
    open_ports = [port for port in host.get("ports", []) if port.get("state") == "open"]
    lines = [
        f"  Host {index}",
        f"    IPv4: {host['ip']}",
        f"    MAC: {host.get('mac') or 'unknown'}",
        f"    ARP RTT: {_display(host.get('arp_rtt_ms'))} ms",
        f"    TCP Probes: {summary['total']}",
        f"    Open TCP Ports: {len(open_ports)}",
    ]
    if failures:
        lines.append(f"    Probe Warning: {failures} probes timed out, were unreachable, or failed.")
    lines.extend(
        f"      Port: {port['port']}/{port['proto']} | State: {port['state']} | "
        f"Latency: {_display(port.get('latency_ms'))} ms"
        for port in open_ports
    )
    if not open_ports:
        message = (
            "No conclusive TCP port result was obtained for this host."
            if summary["total"] and failures == summary["total"]
            else "No open TCP ports found on this host."
        )
        lines.append(f"      {message}")
    return lines


def render_csv(payload: Payload) -> str:
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for host in payload.get("hosts", []) or (None,):
        ports = host.get("ports", []) or (None,) if host is not None else (None,)
        for port in ports:
            row = _csv_row(payload, host, port)
            writer.writerow({key: _csv_safe(value) for key, value in row.items()})
    return buffer.getvalue()


def _csv_row(
    payload: Payload, host: dict[str, Any] | None, port: dict[str, Any] | None
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "schema_version": payload.get("schema_version", SCHEMA_VERSION),
        "scan_id": payload["scan_id"],
        "command": payload["command"],
        "target": str(payload.get("inputs", {}).get("target", "")),
        "started_at": payload.get("started_at", ""),
        "finished_at": payload.get("finished_at", ""),
    }
    if host is None:
        return row | {"record_type": "scan", "status": scan_status(payload)}

    summary = _summary(host)
    failures = _failure_count(summary)
    status = (
        "probe-failure" if summary["total"] and failures == summary["total"]
        else "partial-probe-failure" if failures
        else "completed" if summary["open"]
        else "no-open-ports" if summary["total"]
        else "not-scanned"
    )
    row.update(
        host_ip=host["ip"],
        host_mac=host.get("mac") or "",
        arp_rtt_ms=_display(host.get("arp_rtt_ms"), ""),
        record_type="host" if port is None else "port",
        status=status,
        total_probes=summary["total"],
        **{f"{state}_count": summary[state] for state in PROBE_STATES},
    )
    if port is not None:
        row.update({field: _display(port.get(field), "") for field in PORT_FIELDS})
    return row


def _csv_safe(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    first = next(
        (index for index, char in enumerate(value) if not char.isspace() and not unicodedata.category(char).startswith("C")),
        len(value),
    )
    leading_control = any(unicodedata.category(char).startswith("C") for char in value[:first])
    return f"'{value}" if leading_control or value[first:].startswith(FORMULA_PREFIXES) else value


def _display(value: Any, empty: str = "-") -> str:
    return empty if value is None else str(value)
