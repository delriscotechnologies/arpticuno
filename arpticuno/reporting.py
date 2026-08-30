from __future__ import annotations

import csv
import json
import unicodedata
from collections import defaultdict
from datetime import datetime, timezone
from io import StringIO
from typing import Any
from uuid import uuid4

from arpticuno import __version__
from arpticuno.scanner import STATES, Host, PortResult

TOP_ART = r'''      db                           mm     db
     ;MM:                          MM
    ,V^MM.    `7Mb,od8 `7MMpdMAo.mmMMmm `7MM  ,p6"bo `7MM  `7MM  `7MMpMMMb.  ,pW"Wq.
   ,M  `MM      MM' "'   MM   `Wb  MM     MM 6M'  OO   MM    MM    MM    MM 6W'   `Wb
   AbmmmqMA     MM       MM    M8  MM     MM 8M        MM    MM    MM    MM 8M     M8
  A'     VML    MM       MM   ,AP  MM     MM YM.    ,  MM    MM    MM    MM YA.   ,A9
.AMA.   .AMMA..JMML.     MMbmmd'   `Mbmo.JMML.YMbmd'   `Mbod"YML..JMML  JMML.`Ybmd9'
                         MM
                       .JMML.'''
BANNER = "+--------------------------+\n|  Del Risco Technologies  |\n+--------------------------+"
CSV_FIELDS = ["scan_id", "command", "target", "host_ip", "host_mac", "resolve_ms", "port", "proto", "state", "latency_ms", "error", "started_at", "finished_at", "record_type", "status", "total_probes", "open_count", "closed_count", "timeout_count", "unreachable_count", "error_count", "schema_version"]
FAILURES = ("timeout", "unreachable", "error")
def branding() -> str:
    width = max(map(len, TOP_ART.splitlines()))
    banner = "\n".join(line.center(width).rstrip() for line in BANNER.splitlines())
    return f"{TOP_ART}\n\n{banner}\n\n"
def _summary(host: dict[str, Any]) -> dict[str, int]:
    supplied = host.get("probe_summary", {})
    counts = {state: max(0, int(supplied.get(state, 0))) for state in STATES}
    return {"total": max(int(supplied.get("total", 0)), sum(counts.values())), **counts}
def scan_status(payload: dict[str, Any]) -> str:
    hosts = payload.get("hosts", [])
    if not hosts:
        return "no-resolved-hosts"
    summaries = [_summary(host) for host in hosts]
    failed = lambda summary: sum(summary[state] for state in FAILURES)
    if all(summary["total"] and failed(summary) == summary["total"] for summary in summaries):
        return "inconclusive"
    if any(failed(summary) for summary in summaries):
        return "partial"
    return "completed" if any(summary["open"] for summary in summaries) else "no-open-ports"
def build_payload(
    target: str, ports_text: str, iface: str | None, retries: int, connect_timeout: float,
    workers: int, hosts: list[Host], ports: list[PortResult],
    summaries: dict[str, dict[str, int]], started: str,
) -> dict[str, Any]:
    grouped: defaultdict[str, list[PortResult]] = defaultdict(list)
    for result in ports:
        grouped[result.host].append(result)
    host_data = []
    for host in hosts:
        host_data.append({
            "ip": host.ip, "mac": host.mac, "resolve_ms": host.resolve_ms,
            "ports": [
                {"port": item.port, "proto": "tcp", "state": item.state, "latency_ms": item.latency_ms, "error": None}
                for item in grouped[host.ip]
            ],
            "probe_summary": summaries.get(host.ip, {"total": 0, **dict.fromkeys(STATES, 0)}),
        })
    payload = {
        "schema_version": "2.0", "tool": "Arpticuno", "version": __version__, "scan_id": str(uuid4()),
        "command": "scan", "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {"target": target, "ports": ports_text, "iface": iface, "retries": retries,
                   "connect_timeout": connect_timeout, "workers": workers},
        "hosts": host_data,
    }
    payload["status"] = scan_status(payload)
    return payload
def render_table(payload: dict[str, Any]) -> str:
    hosts = payload.get("hosts", [])
    total = sum(_summary(host)["total"] for host in hosts)
    opened = sum(len(host.get("ports", [])) for host in hosts)
    lines = [
        f"Results: Target(s): {payload.get('inputs', {}).get('target') or '-'} | Resolved hosts: {len(hosts)} | TCP probes: {total} | Open TCP ports: {opened}",
        f"Status: {scan_status(payload)}", "", "Resolved hosts:",
    ]
    if not hosts:
        lines.append("  No hosts resolved.")
    for index, host in enumerate(hosts, 1):
        if index > 1:
            lines.append("")
        summary = _summary(host)
        failures = sum(summary[state] for state in FAILURES)
        lines += [f"  Host {index}", f"    IPv4: {host['ip']}", f"    MAC: {host.get('mac') or 'unknown'}",
                  f"    Resolve time: {host.get('resolve_ms') if host.get('resolve_ms') is not None else '-'} ms",
                  f"    TCP Probes: {summary['total']}", f"    Open TCP Ports: {len(host.get('ports', []))}"]
        if failures:
            lines.append(f"    Probe Warning: {failures} probes timed out, were unreachable, or failed.")
        lines += [f"      Port: {port['port']}/{port['proto']} | State: {port['state']} | Latency: {port.get('latency_ms', '-')} ms" for port in host.get("ports", [])]
        if not host.get("ports"):
            message = "No conclusive TCP port result was obtained for this host." if summary["total"] and failures == summary["total"] else "No open TCP ports found on this host."
            lines.append(f"      {message}")
    return "\n".join(lines) + "\n"
def _csv_safe(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    index = next((i for i, char in enumerate(value) if not char.isspace() and not unicodedata.category(char).startswith("C")), len(value))
    unsafe = any(unicodedata.category(char).startswith("C") for char in value[:index]) or value[index:].startswith(("=", "+", "-", "@"))
    return f"'{value}" if unsafe else value
def render_csv(payload: dict[str, Any]) -> str:
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    hosts = payload.get("hosts", [])
    for host in hosts or [None]:
        for port in (host.get("ports", []) or [None]) if host else [None]:
            row = {"schema_version": payload["schema_version"], "scan_id": payload["scan_id"], "command": payload["command"], "target": payload["inputs"]["target"], "started_at": payload["started_at"], "finished_at": payload["finished_at"]}
            if host is None:
                row |= {"record_type": "scan", "status": scan_status(payload)}
            else:
                summary = _summary(host)
                failed = sum(summary[state] for state in FAILURES)
                status = "probe-failure" if summary["total"] and failed == summary["total"] else "partial-probe-failure" if failed else "completed" if summary["open"] else "no-open-ports" if summary["total"] else "not-scanned"
                row |= {"host_ip": host["ip"], "host_mac": host.get("mac") or "", "resolve_ms": host.get("resolve_ms") if host.get("resolve_ms") is not None else "", "record_type": "host" if port is None else "port", "status": status, "total_probes": summary["total"], **{f"{state}_count": summary[state] for state in STATES}}
                if port:
                    row |= {key: port.get(key, "") for key in ("port", "proto", "state", "latency_ms", "error")}
            writer.writerow({key: _csv_safe(value) for key, value in row.items()})
    return buffer.getvalue()
def render(payload: dict[str, Any], fmt: str) -> str:
    return json.dumps(payload, indent=2, allow_nan=False) + "\n" if fmt == "json" else render_csv(payload) if fmt == "csv" else render_table(payload)
