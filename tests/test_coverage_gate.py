from pathlib import Path

import pytest

from tools.check_coverage import measure_coverage


def test_measure_coverage_counts_only_matching_package_reports(tmp_path: Path):
    source_root = tmp_path / "arpticuno"
    source_root.mkdir()
    (source_root / "cli.py").write_text("print('x')\n", encoding="utf-8")

    report_root = tmp_path / "reports"
    report_root.mkdir()
    (report_root / "home.runner.arpticuno.cli.cover").write_text(
        "    1: line one\n>>>>>> line two\n    2: line three\n",
        encoding="utf-8",
    )
    (report_root / "home.runner.tests.test_cli.cover").write_text(
        ">>>>>> unrelated\n",
        encoding="utf-8",
    )

    assert measure_coverage(report_root, source_root) == (2, 3)


def test_measure_coverage_rejects_missing_reports(tmp_path: Path):
    source_root = tmp_path / "arpticuno"
    source_root.mkdir()
    (source_root / "cli.py").write_text("print('x')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="No executable coverage reports"):
        measure_coverage(tmp_path / "reports", source_root)
