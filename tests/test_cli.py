import json
from io import StringIO

import pytest

import arpticuno.cli as cli
from arpticuno.cli import INCONCLUSIVE_EXIT_CODE, _make_progress_reporter, _print_branding, build_parser, main
from arpticuno.discovery import Host
from arpticuno.ports import PortResult


def _host():
    return [Host(ip="192.168.1.10", mac="aa:bb:cc:dd:ee:ff", rtt_ms=2.0)]


def test_parser_exposes_scan_and_operational_options():
    help_text = build_parser().format_help()
    assert "scan" in help_text
    scan_help = build_parser()._subparsers._group_actions[0].choices["scan"].format_help()
    for option in (
        "--ports",
        "--workers",
        "--connect-timeout",
        "--output",
        "--no-banner",
        "--fail-on-inconclusive",
    ):
        assert option in scan_help


def test_default_scan_preserves_documented_defaults(capsys):
    code = main(
        ["scan", "192.168.1.10", "--format", "json"],
        arp_discover=lambda *args: _host(),
        probe=lambda host, port, timeout: PortResult(host=host, port=port, state="open"),
        ports_provider=lambda: [22],
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["inputs"]["port_range"] == "1-7000"
    assert "workers" not in payload["inputs"]
    assert "connect_timeout" not in payload["inputs"]


def test_scan_accepts_custom_ports_workers_and_timeout(capsys):
    calls = []

    def probe(host, port, timeout):
        calls.append((host, port, timeout))
        return PortResult(host=host, port=port, state="open" if port == 22 else "closed")

    code = main(
        [
            "scan",
            "192.168.1.10",
            "--ports",
            "22,80",
            "--workers",
            "2",
            "--connect-timeout",
            "0.5",
            "--format",
            "json",
            "--no-banner",
        ],
        arp_discover=lambda *args: _host(),
        probe=probe,
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert sorted(port for _, port, _ in calls) == [22, 80]
    assert all(timeout == 0.5 for _, _, timeout in calls)
    assert payload["inputs"]["ports"] == "22,80"
    assert payload["inputs"]["workers"] == 2
    assert payload["inputs"]["connect_timeout"] == 0.5


def test_scan_can_write_output_file(tmp_path, capsys):
    output = tmp_path / "result.json"
    code = main(
        ["scan", "192.168.1.10", "--ports", "22", "--format", "json", "--output", str(output)],
        arp_discover=lambda *args: _host(),
        probe=lambda host, port, timeout: PortResult(host=host, port=port, state="open"),
    )
    assert code == 0
    assert capsys.readouterr().out == ""
    assert json.loads(output.read_text())["schema_version"] == "1.0"


def test_fail_on_inconclusive_returns_documented_code(capsys):
    code = main(
        ["scan", "192.168.1.10", "--ports", "22", "--format", "json", "--fail-on-inconclusive"],
        arp_discover=lambda *args: _host(),
        probe=lambda host, port, timeout: PortResult(
            host=host,
            port=port,
            state="timeout",
            error="timeout",
        ),
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == INCONCLUSIVE_EXIT_CODE
    assert payload["status"] == "inconclusive"


def test_no_banner_suppresses_branding():
    output = StringIO()
    code = main(
        ["scan", "192.168.1.10", "--ports", "22", "--no-banner"],
        arp_discover=lambda *args: [],
        stdout=output,
        stderr=StringIO(),
    )
    assert code == 0
    assert "Del Risco Technologies" not in output.getvalue()
    assert "Results:" in output.getvalue()


def test_invalid_options_return_input_error(capsys):
    for args in (
        ["scan", "whoami"],
        ["scan", "192.168.1.10", "--ports", "abc"],
        ["scan", "192.168.1.10", "--workers", "9999"],
        ["scan", "192.168.1.10", "--connect-timeout", "nan"],
    ):
        assert main(args) == 2
        assert "error:" in capsys.readouterr().err


def test_scan_command_shows_friendly_npcap_error_on_windows(capsys, monkeypatch):
    monkeypatch.setattr(cli.sys, "platform", "win32")

    def fail(*args):
        raise RuntimeError("No libpcap provider available")

    assert main(["scan", "192.168.1.0/24"], arp_discover=fail) == 1
    assert "Npcap does not appear to be available" in capsys.readouterr().err


def test_print_branding_and_progress_are_centered():
    class TtyBuffer(StringIO):
        def isatty(self):
            return True

    branding = StringIO()
    _print_branding(branding)
    banner_line = next(
        line for line in branding.getvalue().splitlines() if "Del Risco Technologies" in line
    )
    stream = TtyBuffer()
    reporter = _make_progress_reporter("table", stream)
    assert reporter is not None
    reporter(2, 4, False)
    reporter(None, None, True)
    output = stream.getvalue()
    assert "[████████████████████....................]" in output
    assert "[████████████████████████████████████████]" in output
    assert len(banner_line) == len(banner_line.rstrip())


def test_parser_errors_still_raise_system_exit():
    with pytest.raises(SystemExit) as excinfo:
        main(["scan"])
    assert excinfo.value.code == 2
