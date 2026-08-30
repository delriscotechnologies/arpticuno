# Security policy

## Supported version

Security fixes are applied to the latest version on the `main` branch.

## Reporting a vulnerability

Use GitHub private vulnerability reporting from the repository's **Security** tab. Do not place credentials, private network details, unrelated packet captures, or sensitive reproduction material in a public issue.

Include the affected version, reproduction steps, impact, and suggested mitigation. Any testing must use systems and networks you own or have explicit permission to test.

## Intended scope

The Windows-only Arpticuno CLI accepts private or link-local IPv4 LAN targets. Public IPv4 addresses, hostnames, IPv6, and loopback addresses are rejected by the relevant validation paths. Windows `SendARP` resolves MAC addresses only for destinations on the local subnet.

The implementation bounds target count, total address scope, total ARP requests, discovered hosts, worker count, timeouts, and total TCP probes to reduce accidental resource exhaustion.

## ARP trust boundary

ARP is unauthenticated. A matching reply means only that a response was observed; it does not prove device identity or ownership. If retries return different MAC addresses for one IPv4 address, Arpticuno reports the MAC as unknown.

## Native API and output files

ARP discovery uses the Windows IP Helper API and does not require raw-packet access, Scapy, Npcap, or Administrator privileges. File output rejects directories and symbolic links.

## Dependencies

Arpticuno has no third-party runtime dependencies. Development security tools are pinned exactly in `pyproject.toml`. Automated checks audit dependencies, static analysis, CodeQL results, filesystem findings, and the generated SBOM.
