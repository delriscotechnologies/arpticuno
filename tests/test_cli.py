import json
from io import StringIO

import pytest

import arpticuno.cli as cli
from arpticuno.cli import _make_progress_reporter, _print_branding, build_parser, main
from arpticuno.discovery import Host
from arpticuno.ports import PortResult


def test_parser_exposes_only_scan_command():
    parser = build_parser()
    assert "scan" in parser.format_help()
    assert list(parser._subparsers._group_actions[0].choices) == ["scan"]


def test_scan_command_shows_banner_in_table_mode(capsys):
    def fake_discover(target, iface=None, timeout=1.0, retries=0):
        output_so_far = capsys.readouterr().out
        assert "Del Risco Technologies" in output_so_far
        return []

    code = main(
        ["scan", "192.168.1.0/24"],
        arp_discover=fake_discover,
        probe=lambda host, port, timeout: PortResult(host=host, port=port, proto="tcp", state="closed"),
        ports_provider=lambda: [],
    )

    output = capsys.readouterr().out
    assert code == 0
    assert "Results:" in output
    assert "Target(s):" in output
    assert "│  Total active hosts:" in output


def test_print_branding_centers_del_risco_block():
    stream = StringIO()

    _print_branding(stream)

    lines = stream.getvalue().splitlines()
    banner_lines = [line for line in lines if "Del Risco Technologies" in line or "╔" in line or "╚" in line]
    assert banner_lines
    assert all(line.startswith(" ") for line in banner_lines)
    assert len({len(line) for line in banner_lines}) == 1


def test_scan_command_rejects_removed_worker_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["scan", "192.168.1.0/24", "--workers", "9999"])

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "unrecognized arguments: --workers" in captured.err


def test_scan_command_rejects_invalid_target_text(capsys):
    code = main(["scan", "whoami"])

    captured = capsys.readouterr()
    assert code == 2
    assert "invalid characters" in captured.err


def test_scan_command_rejects_non_finite_arp_timeout(capsys):
    code = main(["scan", "192.168.1.10", "--arp-timeout", "nan", "--format", "json"])

    captured = capsys.readouterr()
    assert code == 2
    assert "ARP timeout" in captured.err


def test_scan_command_shows_friendly_npcap_error_on_windows(capsys, monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "win32")

    def fake_discover(target, iface=None, timeout=1.0, retries=0):
        raise RuntimeError("No libpcap provider available")

    code = main(["scan", "192.168.1.0/24"], arp_discover=fake_discover)

    captured = capsys.readouterr()
    assert code == 1
    assert "Npcap does not appear to be available" in captured.err


def test_scan_command_works_without_specifying_ports(capsys):
    def fake_discover(target, iface=None, timeout=1.0, retries=0):
        assert target == "192.168.1.0/24"
        return [Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", rtt_ms=2.0)]

    def fake_probe(host, port, timeout):
        return PortResult(host=host, port=port, proto="tcp", state="open", latency_ms=1.0)

    code = main(
        ["scan", "192.168.1.0/24", "--format", "json"],
        arp_discover=fake_discover,
        probe=fake_probe,
        ports_provider=lambda: [22, 80],
    )

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["tool"] == "Arpticuno"
    assert payload["command"] == "scan"
    assert payload["inputs"]["target"] == "192.168.1.0/24"
    assert payload["inputs"]["port_range"] == "1-7000"
    assert "connect_timeout" not in payload["inputs"]
    assert "workers" not in payload["inputs"]
    assert [port["port"] for port in payload["hosts"][0]["ports"]] == [22, 80]


def test_progress_reporter_renders_status_for_tty():
    class TtyBuffer(StringIO):
        def isatty(self):
            return True

    branding_stream = StringIO()
    _print_branding(branding_stream)
    banner_line = next(line for line in branding_stream.getvalue().splitlines() if "Del Risco Technologies" in line)

    stream = TtyBuffer()
    reporter = _make_progress_reporter("table", stream)

    assert reporter is not None
    reporter(2, 4, False)
    reporter(None, None, done_flag=True)

    output = stream.getvalue()
    first_progress_line = output.split("\r")[1]
    centered_progress_line = first_progress_line.rstrip("\n")

    def visual_center(line: str) -> float:
        stripped = line.strip()
        left_padding = len(line) - len(line.lstrip(" "))
        return left_padding + ((len(stripped) - 1) / 2)

    assert "[████████████████████....................]" in output
    assert "[████████████████████████████████████████]" in output
    assert "Scanning in progress..." not in output
    assert "Scan complete." not in output
    assert visual_center(centered_progress_line) == visual_center(banner_line)


def test_scan_command_finishes_progress_in_tty_stderr():
    class TtyBuffer(StringIO):
        def isatty(self):
            return True

    def fake_discover(target, iface=None, timeout=1.0, retries=0):
        return [Host(ip="192.168.4.1", mac="aa:bb:cc:dd:ee:ff", rtt_ms=1.0)]

    def fake_probe(host, port, timeout):
        return PortResult(host=host, port=port, proto="tcp", state="closed", latency_ms=0.5)

    stderr = TtyBuffer()
    code = main(
        ["scan", "192.168.4.1"],
        arp_discover=fake_discover,
        probe=fake_probe,
        ports_provider=lambda: [22],
        stderr=stderr,
    )

    assert code == 0
    assert "[████████████████████████████████████████]" in stderr.getvalue()
    assert stderr.getvalue().endswith("\n\n")


def test_scan_command_leaves_space_between_progress_bar_and_results():
    class TtyBuffer(StringIO):
        def isatty(self):
            return True

    def fake_discover(target, iface=None, timeout=1.0, retries=0):
        return [Host(ip="192.168.4.1", mac="aa:bb:cc:dd:ee:ff", rtt_ms=1.0)]

    def fake_probe(host, port, timeout):
        return PortResult(host=host, port=port, proto="tcp", state="closed", latency_ms=0.5)

    stream = TtyBuffer()
    code = main(
        ["scan", "192.168.4.1"],
        arp_discover=fake_discover,
        probe=fake_probe,
        ports_provider=lambda: [22],
        stdout=stream,
        stderr=stream,
    )

    output = stream.getvalue().replace("\r", "")
    last_bar_index = output.rfind("[████████████████████████████████████████]")
    assert code == 0
    assert "\n\nResults:" in output[last_bar_index:]


def test_scan_command_accepts_single_host_target(capsys):
    def fake_discover(target, iface=None, timeout=1.0, retries=0):
        assert target == "192.168.1.10"
        return [Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", rtt_ms=2.0)]

    def fake_probe(host, port, timeout):
        return PortResult(host=host, port=port, proto="tcp", state="open", latency_ms=0.5)

    code = main(
        ["scan", "192.168.1.10", "--format", "json"],
        arp_discover=fake_discover,
        probe=fake_probe,
        ports_provider=lambda: [22],
    )

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["inputs"]["target"] == "192.168.1.10"
    assert payload["hosts"][0]["ip"] == "192.168.1.10"


def test_scan_command_accepts_multiple_targets(capsys):
    def fake_discover(target, iface=None, timeout=1.0, retries=0):
        assert target == "192.168.1.10,192.168.1.20"
        return [
            Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:10", rtt_ms=1.0),
            Host(ip="192.168.1.20", mac="aa:bb:cc:dd:ee:20", rtt_ms=1.2),
        ]

    def fake_probe(host, port, timeout):
        return PortResult(host=host, port=port, proto="tcp", state="open", latency_ms=0.5)

    code = main(
        ["scan", "192.168.1.10,192.168.1.20", "--format", "json"],
        arp_discover=fake_discover,
        probe=fake_probe,
        ports_provider=lambda: [80],
    )

    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["inputs"]["target"] == "192.168.1.10,192.168.1.20"
    assert [host["ip"] for host in payload["hosts"]] == ["192.168.1.10", "192.168.1.20"]


def test_scan_command_uses_arp_then_all_ports_flow(capsys):
    def fake_discover(target, iface=None, timeout=1.0, retries=0):
        return [Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", rtt_ms=2.0)]

    def fake_probe(host, port, timeout):
        return PortResult(host=host, port=port, proto="tcp", state="open", latency_ms=0.5)

    code = main(
        ["scan", "192.168.1.0/24", "--format", "csv"],
        arp_discover=fake_discover,
        probe=fake_probe,
        ports_provider=lambda: [1],
    )

    csv_output = capsys.readouterr().out
    assert code == 0
    assert "scan_id,command,target,host_ip" in csv_output
    assert "192.168.1.10" in csv_output
    assert ",1,tcp,open," in csv_output
