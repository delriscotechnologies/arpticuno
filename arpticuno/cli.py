from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from scapy.error import Scapy_Exception

from arpticuno import __version__
from arpticuno.reporting import branding, build_payload, render, scan_status
from arpticuno.scanner import discover, parse_ports, scan

DEFAULT_PORTS, DEFAULT_TIMEOUT, DEFAULT_WORKERS, INCONCLUSIVE_EXIT = range(1, 7001), 0.2, 256, 3
AUTH_NOTICE = "Use only on systems and networks you own or have explicit permission to test."
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arpticuno", description="Focused IPv4 LAN ARP discovery and TCP connect scanning.",
        epilog=f"Authorization notice: {AUTH_NOTICE}",
    )
    parser.add_argument("--version", action="version", version=f"Arpticuno {__version__}")
    command = parser.add_subparsers(dest="command", required=True).add_parser("scan", help="Discover LAN hosts and scan selected TCP ports")
    command.add_argument("target", help="IPv4 host, CIDR, or comma-separated targets")
    command.add_argument("--iface", help="Interface used for ARP, e.g. eth0")
    command.add_argument("--arp-timeout", type=float, default=1.0, help="ARP timeout in seconds")
    command.add_argument("--retries", type=int, default=0, help="Retries for unanswered ARP requests")
    command.add_argument("--ports", help="TCP ports or ranges (default: 1-7000)")
    command.add_argument("--connect-timeout", type=float, default=DEFAULT_TIMEOUT)
    command.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    command.add_argument("--format", choices=("table", "json", "csv"), default="table")
    command.add_argument("--output", help="Write the report to a UTF-8 file")
    command.add_argument("--no-banner", action="store_true", help="Hide table-mode branding")
    command.add_argument("--fail-on-inconclusive", action="store_true", help=f"Return exit code {INCONCLUSIVE_EXIT} when every TCP probe fails")
    return parser
def _write(path_text: str, content: str) -> None:
    path = Path(path_text).expanduser()
    if path.is_symlink() or path.exists() and not path.is_file():
        raise ValueError(f"Output path is not a regular file: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
        stream.write(content)
def _friendly(exc: Exception) -> str:
    message = str(exc).strip() or exc.__class__.__name__
    if sys.platform.startswith("win") and any(word in message.lower() for word in ("npcap", "winpcap", "libpcap", "pcap", "layer 2 sockets")):
        return "Npcap is unavailable. Install Npcap with WinPcap compatibility mode disabled, then try again."
    return message
def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        ports = parse_ports(args.ports) if args.ports is not None else DEFAULT_PORTS
        started = datetime.now(timezone.utc).isoformat()
        hosts = discover(args.target, args.iface, args.arp_timeout, args.retries)
        open_ports, summaries = scan([host.ip for host in hosts], ports, args.connect_timeout, args.workers)
        payload = build_payload(
            args.target, args.ports or "1-7000", args.arp_timeout, args.iface, args.retries,
            args.connect_timeout, args.workers, hosts, open_ports, summaries, started,
        )
        output = render(payload, args.format)
        if args.output:
            _write(args.output, output)
        else:
            if args.format == "table" and not args.no_banner:
                print(branding(), end="")
            print(output, end="")
        return INCONCLUSIVE_EXIT if args.fail_on_inconclusive and scan_status(payload) == "inconclusive" else 0
    except (TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ImportError, OSError, RuntimeError, Scapy_Exception) as exc:
        print(f"error: {_friendly(exc)}", file=sys.stderr)
        return 1
