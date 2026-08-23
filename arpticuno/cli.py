from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from scapy.error import Scapy_Exception

from arpticuno import __version__
from arpticuno.discovery import Host
from arpticuno.discovery import arp_discover as default_arp_discover
from arpticuno.ports import (
    PortResult,
    Probe,
    parse_ports,
    probe_connect,
    scan_ports_threaded,
    validate_scan_options,
)
from arpticuno.reporting import (
    PROBE_STATES,
    build_payload,
    is_inconclusive,
    render_csv,
    render_json,
    render_table,
)
from arpticuno.ui import BANNER, TOP_ART

DEFAULT_PORTS = range(1, 7001)
DEFAULT_CONNECT_TIMEOUT = 0.2
DEFAULT_WORKERS = 256
INCONCLUSIVE_EXIT_CODE = 3
AUTH_NOTICE = "Use only on systems and networks you own or have explicit permission to test."
ArpDiscover = Callable[[str, str | None, float, int], list[Host]]
ProgressReporter = Callable[[int | None, int | None, bool], None]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arpticuno",
        description="Focused IPv4 LAN ARP discovery and TCP connect scanning.",
        epilog=f"Authorization notice: {AUTH_NOTICE}",
    )
    parser.add_argument("--version", action="version", version=f"Arpticuno {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Discover LAN hosts and scan selected TCP ports")
    scan.add_argument("target", help="IPv4 host, CIDR, or comma-separated targets")
    scan.add_argument("--iface", help="Interface used for ARP, e.g. eth0")
    scan.add_argument("--arp-timeout", type=float, default=1.0, help="ARP timeout in seconds")
    scan.add_argument("--retries", type=int, default=0, help="Retries for unanswered ARP requests")
    scan.add_argument("--ports", help="TCP ports or ranges (default: 1-7000)")
    scan.add_argument("--connect-timeout", type=float, help=f"TCP timeout (default: {DEFAULT_CONNECT_TIMEOUT})")
    scan.add_argument("--workers", type=int, help=f"Concurrent workers (default: {DEFAULT_WORKERS})")
    scan.add_argument("--format", choices=("table", "json", "csv"), default="table")
    scan.add_argument("--output", help="Write the report to a UTF-8 file")
    scan.add_argument("--no-banner", action="store_true", help="Hide table-mode branding")
    scan.add_argument(
        "--fail-on-inconclusive",
        action="store_true",
        help=f"Return exit code {INCONCLUSIVE_EXIT_CODE} when every TCP probe fails",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    arp_discover: ArpDiscover = default_arp_discover,
    probe: Probe = probe_connect,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out, err = stdout or sys.stdout, stderr or sys.stderr
    try:
        args = build_parser().parse_args(argv)
        if args.format == "table" and not args.no_banner and not args.output:
            _print_branding(out)
        progress = _make_progress_reporter(args.format, err)
        payload = _run_command(args, arp_discover=arp_discover, probe=probe, progress=progress)
        if progress:
            progress(None, None, True)
        rendered = _render_payload(payload, args.format)
        if args.output:
            _write_output(args.output, rendered)
        else:
            print(rendered, end="", file=out)
        return INCONCLUSIVE_EXIT_CODE if args.fail_on_inconclusive and is_inconclusive(payload) else 0
    except (TypeError, ValueError) as exc:
        print(f"error: {exc}", file=err)
        return 2
    except (ImportError, OSError, RuntimeError, Scapy_Exception) as exc:
        print(f"error: {_friendly_runtime_error(exc)}", file=err)
        return 1


def _run_command(
    args: argparse.Namespace,
    *,
    arp_discover: ArpDiscover,
    probe: Probe,
    progress: ProgressReporter | None = None,
) -> dict:
    started_at = datetime.now(timezone.utc).isoformat()
    ports = parse_ports(args.ports) if args.ports is not None else DEFAULT_PORTS
    timeout = args.connect_timeout if args.connect_timeout is not None else DEFAULT_CONNECT_TIMEOUT
    workers = args.workers if args.workers is not None else DEFAULT_WORKERS
    validate_scan_options(ports, timeout, workers)
    hosts = arp_discover(args.target, args.iface, args.arp_timeout, args.retries)
    summaries = {host.ip: _empty_probe_summary() for host in hosts}

    def record(result: PortResult) -> None:
        summary = summaries.setdefault(result.host, _empty_probe_summary())
        summary["total"] += 1
        summary[result.state if result.state in PROBE_STATES else "error"] += 1

    results = scan_ports_threaded(
        [host.ip for host in hosts],
        ports,
        timeout=timeout,
        workers=workers,
        probe=probe,
        open_only=True,
        progress=(lambda done, total: progress(done, total, False)) if progress else None,
        result_callback=record,
    )
    return build_payload(
        command="scan",
        inputs={
            "target": args.target,
            "ports": args.ports or "1-7000",
            "arp_timeout": args.arp_timeout,
            "iface": args.iface,
            "retries": args.retries,
            "connect_timeout": timeout,
            "workers": workers,
        },
        hosts=hosts,
        ports=results,
        started_at=started_at,
        probe_summaries=summaries,
    )


def _empty_probe_summary() -> dict[str, int]:
    return {"total": 0, **dict.fromkeys(PROBE_STATES, 0)}


def _write_output(path_text: str, content: str) -> None:
    path = Path(path_text).expanduser()
    if path.is_dir():
        raise ValueError(f"Output path is a directory: {path}")
    path.write_text(content, encoding="utf-8", newline="")


def _print_branding(stream: TextIO) -> None:
    width = max(map(len, TOP_ART.splitlines()))
    banner = "\n".join(line.center(width).rstrip() for line in BANNER.splitlines())
    print(f"\n{TOP_ART}\n\n{banner}\n", file=stream, flush=True)


def _make_progress_reporter(fmt: str, stream: TextIO) -> ProgressReporter | None:
    if fmt != "table" or not getattr(stream, "isatty", lambda: False)():
        return None
    width = 40

    def render(done: int | None, total: int | None, finished: bool = False) -> None:
        ratio = 1.0 if finished else min(max((done or 0) / total, 0.0), 1.0) if total else 0.0
        filled = int(ratio * width)
        bar = f"[{'#' * filled}{'.' * (width - filled)}]"
        print(f"\r{bar.center(max(width + 2, len(bar)))}", end="\n" if finished else "", file=stream, flush=True)

    return render


def _friendly_runtime_error(exc: Exception) -> str:
    message = str(exc).strip() or exc.__class__.__name__
    if sys.platform.startswith("win") and any(
        token in message.lower() for token in ("npcap", "winpcap", "libpcap", "pcap", "layer 2 sockets")
    ):
        return (
            "Npcap is unavailable. Install Npcap with WinPcap-compatible mode disabled, "
            "then run Arpticuno again."
        )
    return message


def _render_payload(payload: dict, fmt: str) -> str:
    if fmt == "json":
        return render_json(payload) + "\n"
    return render_csv(payload) if fmt == "csv" else render_table(payload)


if __name__ == "__main__":
    raise SystemExit(main())
