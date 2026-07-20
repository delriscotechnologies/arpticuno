import json
import re
from pathlib import Path

import pytest

import arpticuno
from arpticuno.discovery import Host
from arpticuno.ports import scan_tcp_ports
from arpticuno.reporting import SCHEMA_VERSION, build_payload, is_inconclusive, render_csv

ROOT = Path(__file__).resolve().parents[1]


def test_package_and_module_versions_stay_in_sync():
    project_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', project_text, flags=re.MULTILINE)
    assert match is not None
    assert match.group(1) == arpticuno.__version__


def test_report_schema_file_matches_runtime_schema_version():
    schema = json.loads((ROOT / "schemas" / "arpticuno-report.schema.json").read_text())
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION


def test_report_status_and_csv_schema_version_are_exposed():
    payload = build_payload(
        command="scan",
        inputs={"target": "192.168.1.10"},
        hosts=[Host(ip="192.168.1.10")],
        ports=[],
        probe_summaries={
            "192.168.1.10": {
                "total": 1,
                "open": 0,
                "closed": 0,
                "timeout": 1,
                "unreachable": 0,
                "error": 0,
            }
        },
    )
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["status"] == "inconclusive"
    assert is_inconclusive(payload)
    assert "schema_version" in render_csv(payload).splitlines()[0]


@pytest.mark.parametrize("bad_port", [True, 22.0, "22", None])
def test_scan_api_rejects_non_integer_ports(bad_port):
    with pytest.raises(ValueError):
        scan_tcp_ports("192.168.1.10", [bad_port])


@pytest.mark.parametrize("bad_workers", [True, 1.5, "2"])
def test_scan_api_rejects_non_integer_workers(bad_workers):
    with pytest.raises(ValueError):
        scan_tcp_ports("192.168.1.10", [22], workers=bad_workers)
