from __future__ import annotations

import argparse
import re
from pathlib import Path

COVERED_LINE = re.compile(r"^\s*\d+:")
MISSED_LINE = ">>>>>>"


def _report_suffixes(source_root: Path) -> set[str]:
    package_name = source_root.name
    suffixes: set[str] = set()
    for source in source_root.rglob("*.py"):
        relative = source.relative_to(source_root).with_suffix("")
        suffixes.add(".".join((package_name, *relative.parts)) + ".cover")
    return suffixes


def measure_coverage(report_root: Path, source_root: Path) -> tuple[int, int]:
    covered = 0
    executable = 0
    suffixes = _report_suffixes(source_root)
    matched_reports = 0

    for report in sorted(report_root.rglob("*.cover")):
        if not any(report.name.endswith(suffix) for suffix in suffixes):
            continue
        matched_reports += 1
        for line in report.read_text(encoding="utf-8").splitlines():
            if COVERED_LINE.match(line):
                covered += 1
                executable += 1
            elif line.startswith(MISSED_LINE):
                executable += 1

    if matched_reports == 0 or executable == 0:
        raise ValueError(f"No executable coverage reports matched {source_root}")
    return covered, executable


def main() -> int:
    parser = argparse.ArgumentParser(description="Enforce line coverage from Python trace reports.")
    parser.add_argument("report_directory", type=Path)
    parser.add_argument("source_directory", type=Path)
    parser.add_argument("minimum", type=float, help="Minimum percentage from 0 through 100")
    args = parser.parse_args()

    if not 0 <= args.minimum <= 100:
        parser.error("minimum must be between 0 and 100")

    covered, executable = measure_coverage(args.report_directory, args.source_directory)
    percentage = covered / executable * 100
    print(f"Arpticuno line coverage: {percentage:.2f}% ({covered}/{executable})")

    if percentage < args.minimum:
        print(f"Coverage is below the required {args.minimum:.2f}% threshold.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
