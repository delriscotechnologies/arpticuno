# Changelog

Notable changes to Arpticuno are recorded here.

## Unreleased

### Changed

- Simplified the repository by removing GitHub workflow, issue-template, test-suite, and coverage-tooling files that were not required to run the application.
- Simplified and fact-checked the README to match the current repository and CLI.
- Updated the security documentation to reflect the current project structure.

### Current capabilities

- Private/link-local IPv4 ARP discovery.
- Bounded TCP connect scanning with configurable ports, workers, and timeouts.
- Table, JSON, and CSV reporting.
- Versioned JSON report schema.
- Synthetic no-network output preview through `python -m arpticuno.sandbox`.

## 0.1.0 - 2026-07-13

### Added

- Initial IPv4 LAN ARP discovery and bounded TCP connect scanning.
- Table, JSON, and CSV reporting.
- Safety limits and authorization boundaries.
