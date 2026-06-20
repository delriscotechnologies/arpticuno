import pytest

from arpticuno.discovery import Host, is_network, parse_ipv4_targets, validate_ipv4_cidr


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
