from __future__ import annotations

import argparse
import math
import sys
from typing import Callable, Sequence, TextIO

from arpticuno import __version__
from arpticuno.discovery import Host, arp_discover as default_arp_discover
from arpticuno.discovery import parse_ipv4_targets
from arpticuno.ports import MAX_TIMEOUT_SECONDS, Probe, probe_connect, scan_ports_threaded
from arpticuno.reporting import build_payload, render_csv, render_json, render_table
from arpticuno.ui import BANNER, TOP_ART

DEFAULT_PORTS = tuple(range(1, 7001))
DEFAULT_CONNECT_TIMEOUT = 0.2
DEFAULT_WORKERS = 256

AUTH_NOTICE = "Use only on systems and networks you own or have explicit permission to test."
MAX_RETRIES = 5
ArpDiscover = Callable[[str, str | None, float, int], list[Host]]
PortProvider = Callable[[], Sequence[int]]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arpticuno",
        description="Arpticuno: simple IPv4 LAN ARP discovery and TCP connect scanner.",
        epilog=f"Authorization notice: {AUTH_NOTICE}",
    )
    parser.add_argument("--version", action="version", version=f"Arpticuno {__version__}")

    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="Discover live IPv4 hosts and scan TCP ports 1-7000")
    scan.add_argument("target", help="IPv4 target: CIDR, single host, or a comma-separated list")
    scan.add_argument("--iface", help="Network interface to use for ARP, e.g. eth0")
    scan.add_argument("--arp-timeout", type=float, default=1.0, help="ARP timeout in seconds")
    scan.add_argument("--retries", type=int, default=0, help="Extra ARP discovery attempts")
    scan.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")

    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    arp_discover: ArpDiscover = default_arp_discover,
    probe: Probe = probe_connect,
    ports_provider: PortProvider = lambda: DEFAULT_PORTS,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    parser = build_parser()
    out = stdout or sys.stdout
    err = stderr or sys.stderr

    try:
        args = parser.parse_args(argv)
        if args.format == "table":
            _print_branding(out)
        progress = _make_progress_reporter(args.format, err)
        payload = _run_command(args, arp_discover=arp_discover, probe=probe, ports_provider=ports_provider, progress=progress)
        if progress is not None:
            progress(None, None, done_flag=True)
    except ValueError as exc:
        print(f"error: {exc}", file=err)
        return 2
    except Exception as exc:  # Friendly failure for scapy/platform/runtime issues.
        print(f"error: {_friendly_runtime_error(exc)}", file=err)
        return 1

    print(_render_payload(payload, args.format), end="", file=out)
    return 0


def _run_command(
    args: argparse.Namespace,
    *,
    arp_discover: ArpDiscover,
    probe: Probe,
    ports_provider: PortProvider,
    progress: Callable[[int | None, int | None, bool], None] | None = None,
) -> dict:
    if args.command != "scan":
        raise ValueError(f"Unknown command: {args.command}")

    parse_ipv4_targets(args.target)
    _validate_scan_options(args)
    hosts = arp_discover(args.target, args.iface, args.arp_timeout, args.retries)
    ports = list(ports_provider())
    results = scan_ports_threaded(
        [host.ip for host in hosts],
        ports,
        timeout=DEFAULT_CONNECT_TIMEOUT,
        workers=DEFAULT_WORKERS,
        probe=probe,
        open_only=True,
        progress=(lambda done, total: progress(done, total, done_flag=False)) if progress is not None else None,
    )
    return build_payload(
        command="scan",
        inputs={
            "target": args.target,
            "port_range": "1-7000",
            "arp_timeout": args.arp_timeout,
            "iface": args.iface,
            "retries": args.retries,
        },
        hosts=hosts,
        ports=results,
    )


def _validate_scan_options(args: argparse.Namespace) -> None:
    if not math.isfinite(args.arp_timeout) or args.arp_timeout <= 0 or args.arp_timeout > MAX_TIMEOUT_SECONDS:
        raise ValueError(f"ARP timeout must be greater than 0 and no more than {MAX_TIMEOUT_SECONDS:g} seconds")
    if args.retries < 0 or args.retries > MAX_RETRIES:
        raise ValueError(f"Retries must be between 0 and {MAX_RETRIES}")


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
            line = f"[{' ' * width}]".replace(" ", ".")
            print(f"\r{_center_line(line)}", end="", file=stream, flush=True)
            return

        percent = min(max(done or 0, 0) / total, 1.0)
        filled = int(percent * width)
        bar = "█" * filled + "." * (width - filled)
        line = f"[{bar}]"
        print(f"\r{_center_line(line)}", end="", file=stream, flush=True)

    return render


def _friendly_runtime_error(exc: Exception) -> str:
    message = str(exc).strip() or exc.__class__.__name__
    lowered = message.lower()
    if sys.platform.startswith("win") and any(
        token in lowered for token in ("npcap", "winpcap", "libpcap", "pcap", "layer 2 sockets")
    ):
        return (
            "Npcap does not appear to be available on this Windows system. "
            "Please install Npcap, enable WinPcap-compatible mode during setup, then run Arpticuno again."
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
