import argparse
from collections.abc import Sequence

from arpticuno.reporting import branding, build_payload, render
from arpticuno.scanner import STATES, Host, PortResult

HOSTS = [Host("192.168.1.1", "aa:bb:cc:dd:ee:01", 1.2), Host("192.168.1.10", "aa:bb:cc:dd:ee:10", 2.7), Host("192.168.1.25", "aa:bb:cc:dd:ee:25", 3.4)]
PORTS = [PortResult("192.168.1.1", 53, "open", 0.8), PortResult("192.168.1.1", 80, "open", 0.9), PortResult("192.168.1.10", 22, "open", 1.4), PortResult("192.168.1.10", 443, "open", 1.8), PortResult("192.168.1.25", 3389, "open", 2.1)]
def build_demo_payload() -> dict:
    summaries = {
        host.ip: {"total": 7000, **dict.fromkeys(STATES, 0), "open": sum(port.host == host.ip for port in PORTS),
                  "closed": 7000 - sum(port.host == host.ip for port in PORTS)} for host in HOSTS
    }
    return build_payload("192.168.1.0/24", "1-7000", None, 0, 0.2, 256, HOSTS, PORTS, summaries, "1970-01-01T00:00:00+00:00")
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview Arpticuno without network traffic")
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument("--no-banner", action="store_true")
    args = parser.parse_args(argv)
    if args.format == "table" and not args.no_banner:
        print(branding(), end="")
    print(render(build_demo_payload(), args.format), end="")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
