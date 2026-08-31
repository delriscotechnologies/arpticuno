# Security policy

## Supported version

Security fixes are applied to the latest version on the `main` branch.

## Reporting a vulnerability

Use the repository's **Security** tab and **Report a vulnerability** when that option is available. If it is unavailable, open a minimal public issue requesting a private reporting channel and do not include sensitive details.

Include the affected version, reproduction steps, impact, and suggested mitigation. Test only systems and networks you own or have explicit permission to test.

## Intended scope

Arpticuno accepts RFC1918 private or IPv4 link-local targets. Public IPv4 addresses, hostnames, IPv6, and loopback addresses are rejected. Physical-address resolution is limited to destinations on the local subnet.

The implementation bounds target count, worst-case `SendARP` calls, resolved hosts, worker count, TCP timeout, and total TCP probes.

## Resolution trust boundary

ARP is unauthenticated. A resolved IPv4-to-MAC mapping does not prove device identity or ownership and may come from the local ARP table.

## Output files

File output rejects directories and symbolic links.

## Dependencies

Arpticuno has no third-party runtime dependencies.
