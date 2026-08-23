from types import SimpleNamespace

import pytest

from arpticuno import discovery


def test_parse_targets_collapses_hosts_and_networks() -> None:
    targets = discovery.parse_ipv4_targets(
        "192.168.1.0,192.168.1.1,192.168.1.2/31,10.0.0.1"
    )
    assert [str(target) for target in targets] == ["10.0.0.1/32", "192.168.1.0/30"]


@pytest.mark.parametrize(
    "target",
    ["", "8.8.8.8", "192.168.1.4/24", "2001:db8::1", "192.168.1.1,"],
)
def test_parse_targets_rejects_invalid_scope(target: str) -> None:
    with pytest.raises(ValueError):
        discovery.parse_ipv4_targets(target)


def test_arp_budget_counts_addresses_and_retries() -> None:
    discovery.validate_arp_options(1.0, 0, 65_536)
    with pytest.raises(ValueError, match="131,072 requests"):
        discovery.validate_arp_options(1.0, 1, 65_536)


def test_validate_local_host_normalizes_and_rejects_public_addresses() -> None:
    assert discovery.validate_local_ipv4_host(" 192.168.1.1 ") == "192.168.1.1"
    with pytest.raises(ValueError):
        discovery.validate_local_ipv4_host("1.1.1.1")


def test_arp_discover_uses_multi_and_reports_mac_conflicts(monkeypatch) -> None:
    monkeypatch.setattr(discovery, "_direct_interface", lambda network, requested: "test0")
    request_a = SimpleNamespace(sent_time=10.0)
    request_b = SimpleNamespace(sent_time=20.0)
    answers = [
        (request_a, SimpleNamespace(psrc="192.168.1.2", hwsrc="AA:BB:CC:DD:EE:01", time=10.003)),
        (request_b, SimpleNamespace(psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:02", time=20.005)),
        (request_b, SimpleNamespace(psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:03", time=20.002)),
        (request_a, SimpleNamespace(psrc="192.168.2.1", hwsrc="aa:bb:cc:dd:ee:04", time=10.001)),
    ]
    calls = []

    def fake_sender(packet, **kwargs):
        calls.append(kwargs)
        return answers, []

    hosts = discovery.arp_discover(
        "192.168.1.0/30", timeout=0.5, retries=1, send_receive=fake_sender
    )

    assert hosts == [
        discovery.Host("192.168.1.1", None, 2.0),
        discovery.Host("192.168.1.2", "aa:bb:cc:dd:ee:01", 3.0),
    ]
    assert calls == [
        {"iface": "test0", "timeout": 0.5, "retry": 1, "multi": True, "verbose": False}
    ]


def test_direct_interface_rejects_routed_target(monkeypatch) -> None:
    import scapy.all

    route = SimpleNamespace(route=lambda *args, **kwargs: ("eth0", "192.168.1.2", "192.168.1.1"))
    monkeypatch.setattr(scapy.all.conf, "route", route)
    network = discovery.parse_ipv4_targets("10.0.0.0/24")[0]
    with pytest.raises(ValueError, match="not directly connected"):
        discovery._direct_interface(network, None)
