from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass


MAX_ARP_TARGETS = 65_536
MAX_DISCOVERED_HOSTS = 256
LOCAL_IPV4_RANGES: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)


@dataclass(frozen=True)
class Host:
    ip: str
    mac: str | None = None
    rtt_ms: float | None = None


def parse_ipv4_targets(value: str) -> list[ipaddress.IPv4Network]:
    """Validate one or more IPv4 targets for ARP discovery.

    Accepted forms:
    - single IPv4 CIDR: 192.168.1.0/24
    - single IPv4 host: 192.168.1.10
    - comma-separated mix: 192.168.1.10,192.168.1.20,192.168.2.0/24
    """
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Target is required. Use an IPv4 like 192.168.1.10 or CIDR like 192.168.1.0/24")
    if not re.fullmatch(r"[0-9./,\s]+", cleaned):
        raise ValueError(
            "Target contains invalid characters. Use only digits, dots, commas, spaces, and / in IPv4 targets like 192.168.1.10 or 192.168.1.0/24"
        )

    raw_targets = [part.strip() for part in cleaned.split(",")]
    if any(not part for part in raw_targets):
        raise ValueError("Target list contains an empty entry. Remove extra commas and try again.")

    networks: list[ipaddress.IPv4Network] = []
    total_addresses = 0
    for raw_target in raw_targets:
        network = _parse_single_ipv4_target(raw_target)
        total_addresses += network.num_addresses
        if total_addresses > MAX_ARP_TARGETS:
            raise ValueError("Target list is too large for safe LAN ARP discovery. Use /16 or smaller total scope.")
        networks.append(network)
    return networks


def validate_ipv4_cidr(value: str) -> ipaddress.IPv4Network:
    """Backwards-compatible strict CIDR validator used by older callers/tests."""
    network = _parse_single_ipv4_target(value)
    if network.prefixlen == 32 and "/" not in value:
        raise ValueError(
            "Target must be an IPv4 CIDR network like 192.168.1.0/24. This validator does not accept plain IPs, hostnames, or commands."
        )
    if "/" not in value:
        raise ValueError(
            "Target must be an IPv4 CIDR network like 192.168.1.0/24. This validator does not accept plain IPs, hostnames, or commands."
        )
    return network


def _parse_single_ipv4_target(value: str) -> ipaddress.IPv4Network:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Target is required. Use an IPv4 like 192.168.1.10 or CIDR like 192.168.1.0/24")

    try:
        if "/" in cleaned:
            network = ipaddress.ip_network(cleaned, strict=True)
        else:
            host = ipaddress.ip_address(cleaned)
            network = ipaddress.ip_network(f"{host}/32", strict=True)
    except ValueError as exc:
        hint = "192.168.1.10" if "/" not in cleaned else "192.168.1.0/24"
        raise ValueError(f"Invalid IPv4 target: {cleaned}. Example: {hint}") from exc

    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("ARP discovery only supports IPv4 targets")
    if not any(network.subnet_of(local_range) for local_range in LOCAL_IPV4_RANGES):
        raise ValueError("ARP discovery is limited to private/link-local IPv4 LAN ranges")
    if network.num_addresses > MAX_ARP_TARGETS:
        raise ValueError("CIDR is too large for safe LAN ARP discovery. Use /16 or narrower.")
    return network


def is_network(value: str) -> bool:
    """Return True only when the input looks like CIDR/network input."""
    if "/" not in value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def arp_discover(
    target: str,
    iface: str | None = None,
    timeout: float = 1.0,
    retries: int = 0,
) -> list[Host]:
    """Discover live IPv4 hosts on the local LAN using ARP broadcast."""
    targets = parse_ipv4_targets(target)

    from scapy.all import ARP, Ether, srp  # type: ignore

    discovered: dict[str, Host] = {}

    for network in targets:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        for _ in range(max(0, retries) + 1):
            answered, _ = srp(packet, iface=iface, timeout=timeout, verbose=False)

            for request, reply in answered:
                try:
                    reply_ip = ipaddress.ip_address(str(reply.psrc))
                except ValueError:
                    continue
                if not isinstance(reply_ip, ipaddress.IPv4Address) or reply_ip not in network:
                    continue

                ip = str(reply_ip)
                discovered[ip] = Host(
                    ip=ip,
                    mac=str(reply.hwsrc),
                    rtt_ms=_arp_rtt_ms(request, reply),
                )
                if len(discovered) > MAX_DISCOVERED_HOSTS:
                    raise ValueError(
                        f"ARP discovery returned more than {MAX_DISCOVERED_HOSTS} hosts. "
                        "Use a narrower target scope."
                    )

    return [discovered[ip] for ip in sorted(discovered, key=ipaddress.ip_address)]


def _arp_rtt_ms(request: object, reply: object) -> float | None:
    """Return Scapy's per-packet ARP round-trip time when timestamps are available."""
    sent_at = getattr(request, "sent_time", None)
    received_at = getattr(reply, "time", None)
    if sent_at is None or received_at is None:
        return None
    try:
        elapsed = float(received_at) - float(sent_at)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(elapsed) or elapsed < 0:
        return None
    return round(elapsed * 1000.0, 2)
