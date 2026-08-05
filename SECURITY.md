# Security policy

## Supported version

Security fixes are applied to the latest version on the `main` branch. Published releases are not considered supported after a newer security release is available unless explicitly stated otherwise.

## Reporting a vulnerability

Use GitHub private vulnerability reporting in the repository's **Security** tab. Do not publish credentials, private network details, packet captures containing unrelated traffic, or working exploit material in a public issue.

Include the affected version, reproduction steps, impact, and suggested mitigation. Reports involving scans must use systems and networks you own or have explicit permission to test.

## Intended scope

The Arpticuno CLI and batch scan APIs accept only private or link-local IPv4 LAN targets. They reject public IPv4 addresses, hostnames, IPv6 addresses, loopback addresses, malformed ARP replies, and replies outside the requested target.

ARP target lists are limited to 256 raw entries and 65,536 unique addresses. Duplicate and overlapping networks are collapsed, and target networks plus retries cannot exceed 512 ARP request rounds.

`probe_connect()` is a low-level socket primitive and intentionally does not enforce scope. Applications using it directly are responsible for authorization and target validation.

Host and TCP-probe limits, bounded task submission, strict integer validation, timeouts, retries, and worker limits reduce accidental resource exhaustion. Probe failures remain visible in structured summaries so routing or timeout failures are not mistaken for confirmed closed ports.

## ARP trust boundary

ARP is unauthenticated. A matching reply shows only that a response was observed; it does not prove the identity or ownership of a device. If different MAC addresses are observed for one IPv4 address during a scan, Arpticuno reports the MAC as unknown.

## Privileged execution

Raw ARP access may require elevated privileges. Use the virtual-environment executable by absolute path:

```bash
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.0/24
```

Do not pass an untrusted or user-modifiable `PATH` into `sudo` when launching Arpticuno. Treat output paths as privileged writes when the command is run with `sudo`; choose a trusted destination and correct ownership afterward when necessary.

## Dependency, build, and release security

Scapy is pinned exactly in `pyproject.toml`. Repository CI and development dependencies are resolved with hashes in `uv.lock`, and CI refuses to update that lock during installation. The end-user `pip install .` path uses `pyproject.toml` rather than `uv.lock`; its isolated build environment may select any compatible Hatchling release in the declared range.

CI installs `uv` through the official `astral-sh/setup-uv` action, pins both the action commit and uv version 0.11.29, verifies the version in the primary test matrix, and runs `uv sync --locked --all-extras`.

CI uses minimal token permissions, pinned GitHub Action commits, bounded job timeouts, complete pytest discovery, Ruff, mypy, Bandit, dependency auditing, CodeQL, wheel-content checks, Windows smoke tests, and an isolated Linux network-namespace integration test.

Release tags must match the package version. The release workflow reruns validation, builds wheel and source distributions, generates a CycloneDX SBOM, and publishes only through GitHub's tag-scoped workflow token.
