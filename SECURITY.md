# Security policy

## Supported version

Security fixes are applied to the latest version on the `main` branch.

## Reporting a vulnerability

Use GitHub private vulnerability reporting from the repository's **Security** tab. Do not place credentials, private network details, unrelated packet captures, or sensitive reproduction material in a public issue.

Include the affected version, reproduction steps, impact, and suggested mitigation. Any testing must use systems and networks you own or have explicit permission to test.

## Intended scope

The Arpticuno CLI accepts private or link-local IPv4 LAN targets. Public IPv4 addresses, hostnames, IPv6, loopback addresses, malformed ARP replies, and replies outside the requested scope are rejected by the relevant validation paths.

The implementation bounds target count, total address scope, total ARP requests, discovered hosts, worker count, timeouts, and total TCP probes to reduce accidental resource exhaustion.

## ARP trust boundary

ARP is unauthenticated. A matching reply means only that a response was observed; it does not prove device identity or ownership. If different valid MAC addresses are observed for the same IPv4 address during discovery, Arpticuno reports the MAC as unknown.

## Privileged execution

Raw ARP access may require elevated privileges. When elevated execution is necessary, use the virtual-environment executable directly and choose trusted output locations. File output rejects directories and symbolic links and creates new files with mode `0600` on POSIX systems.

## Dependencies

The runtime Scapy dependency and development security tools are pinned exactly in `pyproject.toml`. Scapy is GPL-2.0-only; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Automated checks audit dependencies, static analysis, CodeQL results, filesystem findings, and the generated SBOM.
