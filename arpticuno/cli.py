from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence, TextIO

from scapy.error import Scapy_Exception

from arpticuno import __version__
from arpticuno.discovery import Host, arp_discover as default_arp_discover, parse_ipv4_targets, validate_arp_options
from arpticuno.ports import PortResult, Probe, parse_ports, probe_connect, scan_ports_threaded
from arpticuno.reporting import PROBE_STATES, build_payload, is_inconclusive, render_csv, render_json, render_table
from arpticuno.ui import BANNER, TOP_ART

DEFAULT_PORTS = tuple(range(1, 7001))
DEFAULT_CONNECT_TIMEOUT = 0.2
DEFAULT_WORKERS = 256
INCONCLUSIVE_EXIT_CODE = 3
AUTH_NOTICE = "Use only on systems and networks you own or have explicit permission to test."
ArpDiscover = Callable[[str, str | None, float, int], list[Host]]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arpticuno",
        description="Arpticuno: focused IPv4 LAN ARP discovery and TCP connect scanner.",
        epilog=f"Authorization notice: {AUTH_NOTICE}",
    )
    parser.add_argument("--version", action="version", version=f"Arpticuno {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan = subcommands.add_parser("scan", help="Find IPv4 hosts that answer ARP and scan selected TCP ports")
    scan.add_argument("target", help="IPv4 target: CIDR, single host, or a comma-separated list")
    scan.add_argument("--iface", help="Network interface to use for ARP, e.g. eth0")
    scan.add_argument("--arp-timeout", type=float, default=1.0, help="ARP timeout in seconds")
    scan.add_argument("--retries", type=int, default=0, help="Extra ARP discovery attempts")
    scan.add_argument("--ports", help="TCP ports or ranges, e.g. 22,80,443,8000-8100 (default: 1-7000)")
    scan.add_argument(
        "--connect-timeout",
        type=float,
        default=None,
        help=f"TCP connect timeout in seconds (default: {DEFAULT_CONNECT_TIMEOUT})",
    )
    scan.add_argument(
        "--workers",
        type=int,
        default=None,
        help=f"Concurrent TCP workers, 1-512 (default: {DEFAULT_WORKERS})",
    )
    scan.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    scan.add_argument("--output", help="Write the report to this file instead of standard output")
    scan.add_argument("--no-banner", action="store_true", help="Hide the banner in table mode")
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
    parser = build_parser()
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    try:
        args = parser.parse_args(argv)
        if args.format == "table" and not args.no_banner:
            _print_branding(out)
        progress = _make_progress_reporter(args.format, err)
        payload = _run_command(
            args,
            arp_discover=arp_discover,
            probe=probe,
            progress=progress,
        )
        if progress is not None:
            progress(None, None, True)
        rendered = _render_payload(payload, args.format)
        if args.output:
            _write_output(args.output, rendered)
        else:
            print(rendered, end="", file=out)
        if args.fail_on_inconclusive and is_inconclusive(payload):
            return INCONCLUSIVE_EXIT_CODE
        return 0
    except ValueError as exc:
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
    progress: Callable[[int | None, int | None, bool], None] | None = None,
) -> dict:
    started_at = datetime.now(timezone.utc).isoformat()
    targets = parse_ipv4_targets(args.target)
    validate_arp_options(args.arp_timeout, args.retries, len(targets))
    ports = parse_ports(args.ports) if args.ports is not None else DEFAULT_PORTS
    connect_timeout = args.connect_timeout if args.connect_timeout is not None else DEFAULT_CONNECT_TIMEOUT
    workers = args.workers if args.workers is not None else DEFAULT_WORKERS
    # Validate TCP controls before any raw-packet operation begins.
    scan_ports_threaded([], ports, timeout=connect_timeout, workers=workers, probe=probe)
    hosts = arp_discover(args.target, args.iface, args.arp_timeout, args.retries)
    probe_summaries = {host.ip: _empty_probe_summary() for host in hosts}

    def record_probe_result(result: PortResult) -> None:
        summary = probe_summaries.setdefault(result.host, _empty_probe_summary())
        state = result.state if result.state in PROBE_STATES else "error"
        summary["total"] += 1
        summary[state] += 1

    results = scan_ports_threaded(
        [host.ip for host in hosts],
        ports,
        timeout=connect_timeout,
        workers=workers,
        probe=probe,
        open_only=True,
        progress=(lambda done, total: progress(done, total, False)) if progress is not None else None,
        result_callback=record_probe_result,
    )
    return build_payload(
        command="scan",
        inputs=_build_inputs(args),
        hosts=hosts,
        ports=results,
        started_at=started_at,
        probe_summaries=probe_summaries,
    )


def _build_inputs(args: argparse.Namespace) -> dict[str, object]:
    inputs: dict[str, object] = {
        "target": args.target,
        "port_range": args.ports or "1-7000",
        "arp_timeout": args.arp_timeout,
        "iface": args.iface,
        "retries": args.retries,
    }
    if args.ports is not None:
        inputs["ports"] = args.ports
    if args.connect_timeout is not None:
        inputs["connect_timeout"] = args.connect_timeout
    if args.workers is not None:
        inputs["workers"] = args.workers
    return inputs


def _write_output(path_text: str, content: str) -> None:
    path = Path(path_text).expanduser()
    if path.exists() and path.is_dir():
        raise ValueError(f"Output path is a directory: {path}")
    path.write_text(content, encoding="utf-8", newline="")


def _empty_probe_summary() -> dict[str, int]:
    return {"total": 0, **{state: 0 for state in PROBE_STATES}}


def _branding_width() -> int:
    return max(len(line.rstrip()) for line in TOP_ART.splitlines())


def _print_branding(stream: TextIO) -> None:
    branding_width = _branding_width()
    centered_banner = "\n".join(line.center(branding_width).rstrip() for line in BANNER.splitlines())
    print(file=stream)
    print(TOP_ART, file=stream)
    print(file=stream)
    print(centered_banner, file=stream)
    print(file=stream, flush=True)


def _center_line(text: str) -> str:
    return text.center(max(_branding_width(), len(text)))


def _make_progress_reporter(
    fmt: str,
    stream: TextIO,
) -> Callable[[int | None, int | None, bool], None] | None:
    if fmt != "table" or not getattr(stream, "isatty", lambda: False)():
        return None

    width = 40

    def render(done: int | None, total: int | None, done_flag: bool = False) -> None:
        if done_flag:
            line = f"[{'█' * width}]"
            print(f"\r{_center_line(line)}", file=stream)
            print(file=stream)
            return
        if not total:
            line = f"[{'.' * width}]"
            print(f"\r{_center_line(line)}", end="", file=stream, flush=True)
            return
        percent = min(max(done or 0, 0) / total, 1.0)
        filled = int(percent * width)
        bar = "█" * filled + "." * (width - filled)
        print(f"\r{_center_line(f'[{bar}]')}", end="", file=stream, flush=True)

    return render


def _friendly_runtime_error(exc: Exception) -> str:
    message = str(exc).strip() or exc.__class__.__name__
    lowered = message.lower()
    if sys.platform.startswith("win") and any(
        token in lowered for token in ("npcap", "winpcap", "libpcap", "pcap", "layer 2 sockets")
    ):
        return (
            "Npcap does not appear to be available on this Windows system. "
            "Please install Npcap, leave WinPcap-compatible mode disabled during setup, then run Arpticuno again."
        )
    return message


def _render_payload(payload: dict, fmt: str) -> str:
    if fmt == "json":
        return render_json(payload) + "\n"
    if fmt == "csv":
        return render_csv(payload)
    return render_table(payload)


if __name__ == "__main__":
    raise SystemExit(main())
