from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, cast

MAX_ARP_TARGETS = 65_536
MAX_ARP_REQUESTS = 65_536
MAX_ARP_TARGET_ENTRIES = 256
MAX_ARP_TIMEOUT_SECONDS = 10.0
MAX_ARP_RETRIES = 5
MAX_DISCOVERED_HOSTS = 256
LOCAL_IPV4_RANGES = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
)
MAC_ADDRESS_PATTERN = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
ArpExchange = tuple[object, object]
SendReceive = Callable[..., tuple[Iterable[ArpExchange], object]]


@dataclass(frozen=True)
class Host:
    ip: str
    mac: str | None = None
    rtt_ms: float | None = None


def validate_local_ipv4_host(value: str) -> str:
    """Return a normalized private or link-local IPv4 host."""
    try:
        address = ipaddress.ip_address(value.strip())
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"Invalid IPv4 host: {value}") from exc
    if address.version != 4:
        raise ValueError("TCP scanning only supports IPv4 hosts")
    if not any(address in local_range for local_range in LOCAL_IPV4_RANGES):
        raise ValueError("TCP scanning is limited to private/link-local IPv4 LAN hosts")
    return str(address)


def validate_arp_options(timeout: float, retries: int, address_count: int = 1) -> None:
    """Validate ARP timing and the maximum packet budget."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout):
        raise ValueError("ARP timeout must be a finite number")
    if not 0 < timeout <= MAX_ARP_TIMEOUT_SECONDS:
        raise ValueError(f"ARP timeout must be greater than 0 and no more than {MAX_ARP_TIMEOUT_SECONDS:g} seconds")
    if isinstance(retries, bool) or not isinstance(retries, int):
        raise TypeError("Retries must be an integer")
    if not 0 <= retries <= MAX_ARP_RETRIES:
        raise ValueError(f"Retries must be between 0 and {MAX_ARP_RETRIES}")
    if isinstance(address_count, bool) or not isinstance(address_count, int) or address_count < 1:
        raise ValueError("ARP discovery requires a positive address count")

    request_count = address_count * (retries + 1)
    if request_count > MAX_ARP_REQUESTS:
        raise ValueError(
            f"ARP discovery could send up to {request_count:,} requests; "
            f"the safety limit is {MAX_ARP_REQUESTS:,}. Use a narrower target or fewer retries."
        )


def parse_ipv4_targets(value: str) -> list[ipaddress.IPv4Network]:
    """Parse hosts, CIDRs, or a comma-separated mix for ARP discovery."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Target is required. Example: 192.168.1.10 or 192.168.1.0/24")
    parts = [part.strip() for part in value.split(",")]
    if any(not part for part in parts):
        raise ValueError("Target list contains an empty entry")
    if len(parts) > MAX_ARP_TARGET_ENTRIES:
        raise ValueError(f"Target list cannot contain more than {MAX_ARP_TARGET_ENTRIES} entries")

    networks = list(ipaddress.collapse_addresses(_parse_target(part) for part in parts))
    address_count = sum(network.num_addresses for network in networks)
    if address_count > MAX_ARP_TARGETS:
        raise ValueError("Target list is too large for safe LAN ARP discovery. Use /16 or narrower.")
    return networks


def _parse_target(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value if "/" in value else f"{value}/32", strict=True)
    except ValueError as exc:
        example = "192.168.1.0/24" if "/" in value else "192.168.1.10"
        raise ValueError(f"Invalid IPv4 target: {value}. Example: {example}") from exc
    if network.version != 4:
        raise ValueError("ARP discovery only supports IPv4 targets")
    if not any(network.subnet_of(local_range) for local_range in LOCAL_IPV4_RANGES):
        raise ValueError("ARP discovery is limited to private/link-local IPv4 LAN ranges")
    return network


def _direct_interface(network: ipaddress.IPv4Network, requested: str | None) -> Any:
    """Return the Scapy interface only when the target is directly connected."""
    from scapy.all import conf  # type: ignore

    interface, _, gateway = conf.route.route(str(network.network_address), dev=requested, verbose=0)
    if gateway is not None and int(ipaddress.IPv4Address(gateway)) != 0:
        raise ValueError(f"ARP target {network} is not directly connected to interface {requested or interface}")
    return requested or interface


def arp_discover(
    target: str,
    iface: str | None = None,
    timeout: float = 1.0,
    retries: int = 0,
    *,
    send_receive: SendReceive | None = None,
) -> list[Host]:
    """Discover ARP responders on directly connected IPv4 networks."""
    targets = parse_ipv4_targets(target)
    validate_arp_options(timeout, retries, sum(network.num_addresses for network in targets))

    from scapy.layers.l2 import ARP, Ether  # type: ignore
    from scapy.sendrecv import srp  # type: ignore

    sender = send_receive or srp
    discovered: dict[str, Host] = {}
    conflicts: set[str] = set()
    for network in targets:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = sender(
            packet,
            iface=_direct_interface(network, iface),
            timeout=timeout,
            retry=retries,
            multi=True,
            verbose=False,
        )
        for request, reply in answered:
            _record_reply(discovered, conflicts, network, request, reply)
            if len(discovered) > MAX_DISCOVERED_HOSTS:
                raise ValueError(f"ARP discovery returned more than {MAX_DISCOVERED_HOSTS} hosts")

    return [discovered[ip] for ip in sorted(discovered, key=ipaddress.ip_address)]


def _record_reply(
    discovered: dict[str, Host],
    conflicts: set[str],
    network: ipaddress.IPv4Network,
    request: object,
    reply: object,
) -> None:
    try:
        reply_ip = ipaddress.ip_address(str(cast(Any, reply).psrc))
    except (AttributeError, ValueError):
        return
    if not isinstance(reply_ip, ipaddress.IPv4Address) or reply_ip not in network:
        return
    mac = _normalize_mac(getattr(reply, "hwsrc", None))
    if mac is None:
        return

    ip = str(reply_ip)
    previous = discovered.get(ip)
    if previous is not None and previous.mac != mac:
        conflicts.add(ip)
    discovered[ip] = Host(
        ip=ip,
        mac=None if ip in conflicts else mac,
        rtt_ms=_minimum_rtt(previous.rtt_ms if previous else None, _arp_rtt_ms(request, reply)),
    )


def _normalize_mac(value: object) -> str | None:
    text = str(value).strip().lower()
    return text if MAC_ADDRESS_PATTERN.fullmatch(text) else None


def _minimum_rtt(first: float | None, second: float | None) -> float | None:
    values = [value for value in (first, second) if value is not None]
    return min(values) if values else None


def _arp_rtt_ms(request: object, reply: object) -> float | None:
    try:
        elapsed = float(cast(Any, reply).time) - float(cast(Any, request).sent_time)
    except (AttributeError, TypeError, ValueError):
        return None
    return round(elapsed * 1000, 2) if math.isfinite(elapsed) and elapsed >= 0 else None
