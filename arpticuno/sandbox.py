from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import TextIO

from arpticuno.cli import _print_branding
from arpticuno.discovery import Host
from arpticuno.ports import PortResult
from arpticuno.reporting import build_payload, render_csv, render_json, render_table

HOST_DATA = (
    ("192.168.1.1", "aa:bb:cc:dd:ee:01", 1.2),
    ("192.168.1.10", "aa:bb:cc:dd:ee:10", 2.7),
    ("192.168.1.25", "aa:bb:cc:dd:ee:25", 3.4),
)
PORT_DATA = (
    ("192.168.1.1", 53, 0.8),
    ("192.168.1.1", 80, 0.9),
    ("192.168.1.10", 22, 1.4),
    ("192.168.1.10", 443, 1.8),
    ("192.168.1.25", 3389, 2.1),
)


def build_demo_payload() -> dict:
    hosts = [Host(*values) for values in HOST_DATA]
    ports = [PortResult(host=host, port=port, state="open", latency_ms=rtt) for host, port, rtt in PORT_DATA]
    summaries = {
        host.ip: {
            "total": 7000,
            "open": sum(result.host == host.ip for result in ports),
            "closed": 7000 - sum(result.host == host.ip for result in ports),
        }
        for host in hosts
    }
    return build_payload(
        command="scan",
        inputs={"target": "192.168.1.0/24", "ports": "1-7000", "sandbox": True},
        hosts=hosts,
        ports=ports,
        probe_summaries=summaries,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Preview Arpticuno without network traffic")
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument("--no-banner", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None) -> int:
    args = build_parser().parse_args(argv)
    out = stdout or sys.stdout
    payload = build_demo_payload()
    if args.format == "table" and not args.no_banner:
        _print_branding(out)
    renderer = {"table": render_table, "json": render_json, "csv": render_csv}[args.format]
    print(renderer(payload), end="" if args.format != "json" else "\n", file=out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
