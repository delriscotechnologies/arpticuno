# Security policy

## Supported version

Security fixes are applied to the latest version on the `main` branch.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting option in the repository's **Security** tab when it is available. Do not publish credentials, private network details, or working exploit material in a public issue.

Include the affected version, reproduction steps, impact, and any suggested mitigation. Reports involving scans must use systems and networks you own or have explicit permission to test.

## Intended scope

The Arpticuno CLI and batch scan APIs accept only private or link-local IPv4 LAN targets. They reject public IPv4 addresses, hostnames, IPv6 addresses, loopback addresses, malformed ARP replies, and ARP replies outside the requested target.

`probe_connect()` is a low-level socket primitive and intentionally does not enforce scope. Applications using it directly are responsible for authorization and target validation.

Host and TCP-probe limits, bounded task submission, timeouts, retries, and worker limits reduce accidental resource exhaustion. Probe failures remain visible in structured summaries so timeouts or routing failures are not mistaken for confirmed closed ports.

## ARP trust boundary

ARP is unauthenticated. A matching reply shows only that an ARP response was observed; it does not prove the identity or ownership of a device. If different MAC addresses are observed for the same IPv4 address during one scan, Arpticuno reports the MAC as unknown rather than selecting one as authoritative.

## Privileged execution

Raw ARP access may require elevated privileges. Use the virtual environment executable by absolute path, for example:

```bash
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.0/24
```

Do not pass an untrusted or user-modifiable `PATH` into `sudo` when launching Arpticuno.

## Dependency and build security

Runtime and development dependencies are version-pinned and resolved through `uv.lock`. CI uses minimal token permissions, pinned GitHub Action commits, bounded job timeouts, dependency auditing, Bandit, Ruff, mypy, pytest, and CodeQL. Third-party license information is recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
