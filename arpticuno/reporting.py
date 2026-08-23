from __future__ import annotations

import csv
import json
import unicodedata
from collections.abc import Iterator
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
FAILURE_STATES = ("timeout", "unreachable", "error")
FORMULA_PREFIXES = ("=", "+", "-", "@")
CSV_FIELDS = (
    "scan_id", "command", "target", "host_ip", "host_mac", "arp_rtt_ms",
    "port", "proto", "state", "latency_ms", "error", "started_at", "finished_at",
    "record_type", "status", "total_probes", "open_count", "closed_count",
    "timeout_count", "unreachable_count", "error_count", "schema_version",
)


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
    ports_by_host: dict[str, list[PortResult]] = {}
    for result in ports:
        ports_by_host.setdefault(result.host, []).append(result)
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
        "hosts": [
            _host_payload(host, ports_by_host.get(host.ip, []), probe_summaries)
            for host in hosts
        ],
    }
    payload["status"] = scan_status(payload)
    return payload


def _host_payload(
    host: Host,
    ports: list[PortResult],
    summaries: dict[str, dict[str, int]] | None,
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
    if summaries is not None:
        payload["probe_summary"] = _normalize_summary(ports, summaries.get(host.ip))
    return payload


def _normalize_summary(
    ports: list[PortResult], supplied: dict[str, int] | None = None
) -> dict[str, int]:
    counts = {state: 0 for state in PROBE_STATES}
    if supplied is None:
        for result in ports:
            counts[result.state if result.state in counts else "error"] += 1
        total = sum(counts.values())
    else:
        counts.update({state: max(0, int(supplied.get(state, 0))) for state in PROBE_STATES})
        total = max(max(0, int(supplied.get("total", 0))), sum(counts.values()))
    return {"total": total, **counts}


def _summary_for_host(host: dict[str, Any]) -> dict[str, int]:
    supplied = host.get("probe_summary")
    if isinstance(supplied, dict):
        return _normalize_summary([], cast(dict[str, int], supplied))
    counts = {state: 0 for state in PROBE_STATES}
    for port in host.get("ports", []):
        state = port.get("state")
        counts[state if state in counts else "error"] += 1
    return {"total": sum(counts.values()), **counts}


def _failures(summary: dict[str, int]) -> int:
    return sum(summary.get(state, 0) for state in FAILURE_STATES)


def scan_status(payload: Payload) -> str:
    hosts = payload.get("hosts", [])
    if not hosts:
        return "no-arp-responders"
    summaries = [_summary_for_host(host) for host in hosts]
    if all(summary["total"] > 0 and _failures(summary) == summary["total"] for summary in summaries):
        return "inconclusive"
    if any(_failures(summary) for summary in summaries):
        return "partial"
    if any(summary["open"] for summary in summaries):
        return "completed"
    return "no-open-ports"


def is_inconclusive(payload: Payload) -> bool:
    return scan_status(payload) == "inconclusive"


def render_json(payload: Payload) -> str:
    return json.dumps(payload, indent=2, allow_nan=False)


def _target(payload: Payload) -> str:
    return str(payload.get("inputs", {}).get("target", ""))


def render_table(payload: Payload) -> str:
    hosts = payload.get("hosts", [])
    total_probes = sum(_summary_for_host(host)["total"] for host in hosts)
    open_count = sum(
        port.get("state") == "open" for host in hosts for port in host.get("ports", [])
    )
    lines = [
        (
            f"Results: Target(s): {_target(payload) or '-'} | ARP responders: {len(hosts)} | "
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
        lines.extend(_render_host(index, host))
    return "\n".join(lines) + "\n"


def _render_host(index: int, host: dict[str, Any]) -> list[str]:
    summary = _summary_for_host(host)
    failures = _failures(summary)
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
    for port in open_ports:
        lines.append(
            f"      Port: {port['port']}/{port['proto']} | State: {port['state']} | "
            f"Latency: {_display(port.get('latency_ms'))} ms"
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
    writer.writerows(_sanitize_csv_row(row) for row in _csv_rows(payload))
    return buffer.getvalue()


def _csv_rows(payload: Payload) -> Iterator[dict[str, Any]]:
    hosts = payload.get("hosts", [])
    if not hosts:
        yield _csv_row(payload)
        return
    for host in hosts:
        ports = host.get("ports", [])
        if ports:
            for port in ports:
                yield _csv_row(payload, host, port)
        else:
            yield _csv_row(payload, host)


def _csv_row(
    payload: Payload,
    host: dict[str, Any] | None = None,
    port: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "schema_version": payload.get("schema_version", SCHEMA_VERSION),
        "scan_id": payload["scan_id"],
        "command": payload["command"],
        "target": _target(payload),
        "started_at": payload.get("started_at", ""),
        "finished_at": payload.get("finished_at", ""),
    }
    if host is None:
        row.update(record_type="scan", status=scan_status(payload))
        return row

    summary = _summary_for_host(host)
    failures = _failures(summary)
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
    if port:
        row.update(
            port=port["port"],
            proto=port["proto"],
            state=port["state"],
            latency_ms=_display(port.get("latency_ms"), ""),
            error=port.get("error") or "",
        )
    return row


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
        leading_control |= is_control
        first_visible += 1
    if leading_control or value[first_visible:].startswith(FORMULA_PREFIXES):
        return f"'{value}"
    return value


def _display(value: Any, empty: str = "-") -> str:
    return empty if value is None else str(value)
