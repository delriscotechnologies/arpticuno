from __future__ import annotations

import argparse
import sys
from typing import Sequence, TextIO

from arpticuno.cli import _print_branding
from arpticuno.discovery import Host
from arpticuno.ports import PortResult
from arpticuno.reporting import build_payload, render_csv, render_json, render_table


def build_demo_payload() -> dict:
    hosts = [
        Host(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", rtt_ms=1.2),
        Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:10", rtt_ms=2.7),
        Host(ip="192.168.1.25", mac="aa:bb:cc:dd:ee:25", rtt_ms=3.4),
    ]
    ports = [
        PortResult(host="192.168.1.1", port=53, proto="tcp", state="open", latency_ms=0.8),
        PortResult(host="192.168.1.1", port=80, proto="tcp", state="open", latency_ms=0.9),
        PortResult(host="192.168.1.10", port=22, proto="tcp", state="open", latency_ms=1.4),
        PortResult(host="192.168.1.10", port=443, proto="tcp", state="open", latency_ms=1.8),
        PortResult(host="192.168.1.25", port=3389, proto="tcp", state="open", latency_ms=2.1),
    ]
    return build_payload(
        command="scan",
        inputs={
            "target": "192.168.1.0/24",
            "port_range": "1-7000",
            "sandbox": True,
        },
        hosts=hosts,
        ports=ports,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m arpticuno.sandbox",
        description="Preview how Arpticuno looks in the terminal without scanning a real network.",
    )
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table")
    parser.add_argument("--no-banner", action="store_true", help="Hide the banner in table mode")
    return parser


def main(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = stdout or sys.stdout
    payload = build_demo_payload()

    if args.format == "table" and not args.no_banner:
        _print_branding(out)

    if args.format == "json":
        print(render_json(payload), file=out)
    elif args.format == "csv":
        print(render_csv(payload), end="", file=out)
    else:
        print(render_table(payload), end="", file=out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
