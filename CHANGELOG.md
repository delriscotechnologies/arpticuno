# Changelog

All notable changes to Arpticuno are documented here. The project follows semantic versioning once a stable release line begins.

## Unreleased

### Added

- Configurable TCP ports, worker count, connect timeout, output file, banner suppression, and inconclusive-result exit handling.
- Versioned JSON/CSV report schema with a published JSON Schema.
- Wheel and source-distribution smoke tests, Windows smoke tests, and a Linux network-namespace integration test.
- Tag-driven GitHub Release workflow with release artifacts and a CycloneDX SBOM.
- Dependency-free 80% package line-coverage gates in CI and release validation.
- Contribution guidance, issue templates, pull-request template, and code of conduct.

### Changed

- TCP API validation now rejects boolean, floating-point, string, and other non-integer port or worker values.
- Package metadata now includes classifiers, project URLs, keywords, and explicit wheel package selection.

## 0.1.0 - 2026-07-13

### Added

- Initial IPv4 LAN ARP discovery and bounded TCP connect scanning.
- Table, JSON, and CSV reporting.
- Safety limits, authorization boundaries, CI, CodeQL, dependency auditing, and security guidance.
