from __future__ import annotations

import errno
import ipaddress
import math
import re
import socket
from collections.abc import Sequence
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from time import perf_counter

MAX_ARP_TARGETS, MAX_ARP_REQUESTS, MAX_TARGET_ENTRIES, MAX_HOSTS, MAX_ARP_RETRIES, MAX_TIMEOUT, MAX_WORKERS, MAX_PROBES = 65_536, 65_536, 256, 256, 5, 10.0, 512, 1_000_000
STATES = ("open", "closed", "timeout", "unreachable", "error")
LOCAL_RANGES = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
)
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
@dataclass(frozen=True)
class Host:
    ip: str
    mac: str | None = None
    rtt_ms: float | None = None
@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    state: str
    latency_ms: float | None = None
def _finite(value: float, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    if not 0 < value <= MAX_TIMEOUT:
        raise ValueError(f"{label} must be greater than 0 and no more than {MAX_TIMEOUT:g} seconds")
    return float(value)
def _local_host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"Invalid IPv4 host: {value}") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise TypeError("TCP scanning only supports IPv4 hosts")
    if not any(address in network for network in LOCAL_RANGES):
        raise ValueError("TCP scanning is limited to private/link-local IPv4 LAN hosts")
    return str(address)
def _targets(text: str) -> list[ipaddress.IPv4Network]:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Target is required. Example: 192.168.1.10 or 192.168.1.0/24")
    parts = [part.strip() for part in text.split(",")]
    if any(not part for part in parts) or len(parts) > MAX_TARGET_ENTRIES:
        raise ValueError(f"Target list must contain 1-{MAX_TARGET_ENTRIES} non-empty entries")
    networks = []
    for part in parts:
        try:
            network = ipaddress.ip_network(part if "/" in part else f"{part}/32", strict=True)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 target: {part}") from exc
        if not isinstance(network, ipaddress.IPv4Network) or not any(network.subnet_of(local) for local in LOCAL_RANGES):
            raise ValueError("ARP discovery is limited to private/link-local IPv4 LAN ranges")
        networks.append(network)
    collapsed = list(ipaddress.collapse_addresses(networks))
    if sum(network.num_addresses for network in collapsed) > MAX_ARP_TARGETS:
        raise ValueError("Target list is too large for safe LAN ARP discovery. Use /16 or narrower.")
    return collapsed
def discover(target: str, iface: str | None, timeout: float, retries: int) -> list[Host]:
    timeout = _finite(timeout, "ARP timeout")
    if isinstance(retries, bool) or not isinstance(retries, int) or not 0 <= retries <= MAX_ARP_RETRIES:
        raise ValueError(f"Retries must be an integer between 0 and {MAX_ARP_RETRIES}")
    networks = _targets(target)
    requests = sum(network.num_addresses for network in networks) * (retries + 1)
    if requests > MAX_ARP_REQUESTS:
        raise ValueError(f"ARP discovery could send {requests:,} requests; the limit is {MAX_ARP_REQUESTS:,}")
    from scapy.all import ARP, Ether, conf, srp  # type: ignore
    found: dict[str, Host] = {}
    conflicts: set[str] = set()
    for network in networks:
        interface, _, gateway = conf.route.route(str(network.network_address), dev=iface, verbose=0)
        if gateway is not None and int(ipaddress.IPv4Address(gateway)):
            raise ValueError(f"ARP target {network} is not directly connected to interface {iface or interface}")
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = srp(packet, iface=iface or interface, timeout=timeout, retry=retries, multi=True, verbose=False)
        for request, reply in answered:
            try:
                address = ipaddress.ip_address(str(reply.psrc))
                mac = str(reply.hwsrc).strip().lower()
            except (AttributeError, ValueError):
                continue
            if not isinstance(address, ipaddress.IPv4Address) or address not in network or not MAC.fullmatch(mac):
                continue
            ip, previous = str(address), found.get(str(address))
            if previous and previous.mac != mac or ip in conflicts:
                conflicts.add(ip)
            try:
                elapsed = (float(str(reply.time)) - float(str(request.sent_time))) * 1000
                rtt = round(elapsed, 2) if math.isfinite(elapsed) and elapsed >= 0 else None
            except (AttributeError, TypeError, ValueError):
                rtt = None
            valid_rtts = [value for value in (previous.rtt_ms if previous else None, rtt) if value is not None]
            found[ip] = Host(ip, None if ip in conflicts else mac, min(valid_rtts) if valid_rtts else None)
            if len(found) > MAX_HOSTS:
                raise ValueError(f"ARP discovery returned more than {MAX_HOSTS} hosts")
    return [found[ip] for ip in sorted(found, key=ipaddress.ip_address)]
def parse_ports(text: str) -> list[int]:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Ports must be non-empty text")
    selected: set[int] = set()
    for item in text.split(","):
        try:
            bounds = [int(value) for value in item.strip().split("-")]
        except ValueError as exc:
            raise ValueError(f"Invalid port list: {text}") from exc
        if len(bounds) not in (1, 2) or any(not 1 <= port <= 65_535 for port in bounds):
            raise ValueError("Ports must be between 1 and 65535")
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise ValueError("Port range start must be less than or equal to end")
        selected.update(range(bounds[0], bounds[-1] + 1))
    return sorted(selected)
def _probe(host: str, port: int, timeout: float) -> PortResult:
    start = perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            state = "open"
    except TimeoutError:
        state = "timeout"
    except OSError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        state = (
            "closed" if code in {errno.ECONNREFUSED, 10061} else
            "timeout" if code in {errno.ETIMEDOUT, 10060} else
            "unreachable" if code in {errno.EHOSTUNREACH, errno.ENETUNREACH, 10051, 10065} else "error"
        )
    return PortResult(host, port, state, round((perf_counter() - start) * 1000, 2))
def scan(hosts: Sequence[str], ports: Sequence[int], timeout: float, workers: int) -> tuple[list[PortResult], dict[str, dict[str, int]]]:
    timeout = _finite(timeout, "TCP connect timeout")
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"Workers must be an integer between 1 and {MAX_WORKERS}")
    checked_hosts = list(dict.fromkeys(_local_host(host) for host in hosts))
    checked_ports = list(dict.fromkeys(ports))
    if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535 for port in checked_ports):
        raise ValueError("Ports must be integers between 1 and 65535")
    total = len(checked_hosts) * len(checked_ports)
    if total > MAX_PROBES:
        raise ValueError(f"Scan would create {total:,} TCP probes; the limit is {MAX_PROBES:,}")
    summaries = {host: {"total": 0, **dict.fromkeys(STATES, 0)} for host in checked_hosts}
    if not total:
        return [], summaries
    jobs = iter(enumerate((host, port) for host in checked_hosts for port in checked_ports))
    results: list[tuple[int, PortResult]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = {}
        def submit() -> bool:
            try:
                index, (host, port) = next(jobs)
            except StopIteration:
                return False
            pending[pool.submit(_probe, host, port, timeout)] = index
            return True
        for _ in range(min(total, workers * 2)):
            submit()
        while pending:
            finished, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
            for future in finished:
                index, result = pending.pop(future), future.result()
                summary = summaries[result.host]
                summary["total"], summary[result.state] = summary["total"] + 1, summary[result.state] + 1
                if result.state == "open":
                    results.append((index, result))
                submit()
    return [result for _, result in sorted(results)], summaries
