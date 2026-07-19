import math
import sys
import types
from types import SimpleNamespace

import pytest

from arpticuno.discovery import (
    MAX_ARP_REQUEST_ROUNDS,
    MAX_ARP_TARGET_ENTRIES,
    Host,
    arp_discover,
    is_network,
    parse_ipv4_targets,
    validate_arp_options,
    validate_ipv4_cidr,
)


def test_host_model_keeps_optional_arp_latency():
    host = Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", rtt_ms=2.4)

    assert host.ip == "192.168.1.10"
    assert host.mac == "aa:bb:cc:dd:ee:ff"
    assert host.rtt_ms == 2.4


def test_is_network_only_true_for_cidr_input():
    assert is_network("192.168.1.0/24") is True
    assert is_network("192.168.1.10") is False


def test_parse_ipv4_targets_accepts_single_host_and_multiple_targets():
    assert [str(item) for item in parse_ipv4_targets("192.168.1.10")] == ["192.168.1.10/32"]
    assert [str(item) for item in parse_ipv4_targets("192.168.1.10, 192.168.1.20, 192.168.2.0/24")] == [
        "192.168.1.10/32",
        "192.168.1.20/32",
        "192.168.2.0/24",
    ]


def test_parse_ipv4_targets_collapses_duplicate_and_overlapping_targets():
    targets = parse_ipv4_targets(
        "192.168.1.10,192.168.1.10,192.168.1.0/25,192.168.1.128/25"
    )

    assert [str(item) for item in targets] == ["192.168.1.0/24"]


def test_validate_ipv4_cidr_rejects_non_ipv4_and_host_bits():
    with pytest.raises(ValueError):
        validate_ipv4_cidr("2001:db8::/64")
    with pytest.raises(ValueError):
        validate_ipv4_cidr("192.168.1.20/24")
    with pytest.raises(ValueError):
        validate_ipv4_cidr("8.8.8.0/24")
    with pytest.raises(ValueError):
        validate_ipv4_cidr("10.0.0.0/15")
    with pytest.raises(ValueError):
        validate_ipv4_cidr("192.168.1.10")

    assert str(validate_ipv4_cidr("192.168.1.0/24")) == "192.168.1.0/24"
    assert str(validate_ipv4_cidr("10.0.0.0/16")) == "10.0.0.0/16"


def test_parse_ipv4_targets_rejects_command_like_input():
    with pytest.raises(ValueError, match="invalid characters"):
        parse_ipv4_targets("whoami")

    with pytest.raises(ValueError, match="invalid characters"):
        parse_ipv4_targets("192.168.1.0/24 && dir")

    with pytest.raises(ValueError, match="empty entry"):
        parse_ipv4_targets("192.168.1.10,,192.168.1.20")


def test_parse_ipv4_targets_rejects_large_aggregate_scope():
    with pytest.raises(ValueError, match="Target list is too large"):
        parse_ipv4_targets("10.0.0.0/16,10.1.0.0/16")


def test_parse_ipv4_targets_rejects_excessive_entry_count():
    target = ",".join(["192.168.1.10"] * (MAX_ARP_TARGET_ENTRIES + 1))

    with pytest.raises(ValueError, match="cannot contain more"):
        parse_ipv4_targets(target)


@pytest.mark.parametrize(
    ("timeout", "retries"),
    [
        (math.nan, 0),
        (0.0, 0),
        (10.1, 0),
        (True, 0),
        (1.0, -1),
        (1.0, 6),
        (1.0, 1.5),
        (1.0, True),
    ],
)
def test_validate_arp_options_rejects_unsafe_values(timeout, retries):
    with pytest.raises(ValueError):
        validate_arp_options(timeout, retries)


def test_validate_arp_options_limits_total_request_rounds():
    target_count = (MAX_ARP_REQUEST_ROUNDS // 6) + 1

    with pytest.raises(ValueError, match="request rounds"):
        validate_arp_options(1.0, 5, target_count)


def test_arp_discover_rejects_spoofed_out_of_scope_replies_and_uses_packet_rtt(monkeypatch):
    class Layer:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def __truediv__(self, other):
            return self, other

    request = SimpleNamespace(sent_time=10.0)
    valid_reply = SimpleNamespace(psrc="192.168.1.10", hwsrc="aa:bb:cc:dd:ee:10", time=10.012)
    spoofed_reply = SimpleNamespace(psrc="8.8.8.8", hwsrc="aa:bb:cc:dd:ee:ff", time=10.020)

    calls = []
    fake_scapy = types.ModuleType("scapy.all")
    fake_scapy.ARP = Layer
    fake_scapy.Ether = Layer

    def fake_srp(*args, **kwargs):
        calls.append((args, kwargs))
        return [(request, valid_reply), (request, spoofed_reply)], []

    fake_scapy.srp = fake_srp
    monkeypatch.setitem(sys.modules, "scapy", types.ModuleType("scapy"))
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy)

    hosts = arp_discover("192.168.1.0/24,192.168.1.0/24")

    assert hosts == [Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:10", rtt_ms=12.0)]
    assert len(calls) == 1


def test_arp_discover_validates_options_before_loading_scapy():
    with pytest.raises(ValueError, match="Retries"):
        arp_discover("192.168.1.10", retries=99)
