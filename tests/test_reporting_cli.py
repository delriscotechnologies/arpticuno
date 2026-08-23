import csv
import io
import json

from arpticuno import cli, sandbox
from arpticuno.discovery import Host
from arpticuno.ports import PortResult
from arpticuno.reporting import build_payload, render_csv, render_json, render_table


def payload_with(state: str) -> dict:
    result = PortResult("192.168.1.2", 80, state, error=state if state != "open" else None)
    return build_payload(
        "scan",
        {"target": "192.168.1.0/24"},
        [Host("192.168.1.2", "aa:bb:cc:dd:ee:ff", 1.5)],
        [result] if state == "open" else [],
        probe_summaries={"192.168.1.2": {"total": 1, state: 1}},
    )


def test_renderers_share_consistent_status_and_ascii_output() -> None:
    payload = payload_with("open")
    table = render_table(payload)
    parsed_json = json.loads(render_json(payload))
    csv_rows = list(csv.DictReader(io.StringIO(render_csv(payload))))

    assert payload["status"] == "completed"
    assert "Status: completed" in table
    assert parsed_json["status"] == "completed"
    assert csv_rows[0]["status"] == "completed"
    table.encode("cp1252")


def test_status_reports_inconclusive_failures() -> None:
    payload = payload_with("timeout")
    assert payload["status"] == "inconclusive"
    assert "No conclusive TCP port result" in render_table(payload)


def test_csv_prevents_formula_injection() -> None:
    payload = build_payload("scan", {"target": "=2+2"}, [], [])
    row = next(csv.DictReader(io.StringIO(render_csv(payload))))
    assert row["target"] == "'=2+2"


def test_cli_runs_complete_injected_scan_without_network() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()

    def discover(target: str, iface, timeout: float, retries: int) -> list[Host]:
        return [Host("192.168.1.2", "aa:bb:cc:dd:ee:ff", 1.0)]

    def probe(host: str, port: int, timeout: float) -> PortResult:
        return PortResult(host, port, "open" if port == 80 else "closed")

    exit_code = cli.main(
        ["scan", "192.168.1.0/24", "--ports", "22,80", "--format", "json"],
        arp_discover=discover,
        probe=probe,
        stdout=stdout,
        stderr=stderr,
    )
    report = json.loads(stdout.getvalue())
    assert exit_code == 0
    assert stderr.getvalue() == ""
    assert report["status"] == "completed"
    assert report["inputs"]["workers"] == cli.DEFAULT_WORKERS
    assert report["hosts"][0]["probe_summary"] == {
        "total": 2,
        "open": 1,
        "closed": 1,
        "timeout": 0,
        "unreachable": 0,
        "error": 0,
    }


def test_cli_inconclusive_exit_code() -> None:
    def discover(target: str, iface, timeout: float, retries: int) -> list[Host]:
        return [Host("192.168.1.2")]

    def probe(host: str, port: int, timeout: float) -> PortResult:
        return PortResult(host, port, "timeout", error="timeout")

    code = cli.main(
        ["scan", "192.168.1.2", "--ports", "80", "--format", "json", "--fail-on-inconclusive"],
        arp_discover=discover,
        probe=probe,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == cli.INCONCLUSIVE_EXIT_CODE


def test_sandbox_is_ascii_safe() -> None:
    output = io.StringIO()
    assert sandbox.main(["--no-banner"], stdout=output) == 0
    assert "Status: completed" in output.getvalue()
    output.getvalue().encode("cp1252")
