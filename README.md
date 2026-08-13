<p align="center">
  <img src="assets/arpticuno-logo.png" alt="Arpticuno" width="420">
</p>

<p align="center">
  Focused IPv4 LAN discovery and TCP connect scanning for authorized environments.
</p>

---

Arpticuno is a small Python CLI for discovering IPv4 hosts on a local private or link-local network and reporting selected TCP connectivity results. It is intentionally limited in scope and does not include advanced scanning, fingerprinting, exploitation, or evasion features.

> Use Arpticuno only on systems and networks you own or have explicit permission to test.

## Requirements

- Python 3.10 or newer
- Scapy 2.7.0
- Local Layer-2 access for ARP discovery
- Elevated privileges when required for raw ARP traffic

Linux is the primary supported environment. On Windows, Scapy requires Npcap for Layer-2 packet access.

## Install

```bash
git clone https://github.com/delriscotechnologies/arpticuno.git
cd arpticuno
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

After installation, use the built-in help for the current command syntax and options:

```bash
arpticuno --help
arpticuno scan --help
```

## What it does

Arpticuno:

1. Validates private or link-local IPv4 targets.
2. Records valid ARP replies within the requested scope.
3. Checks selected TCP ports with normal socket connections.
4. Produces table, JSON, or CSV output.

The default TCP selection is ports `1-7000`. The CLI also supports custom port selections, worker counts, connection timeouts, output files, banner suppression, and an optional inconclusive-result exit code.

## Output

Supported formats:

- `table` — terminal-friendly results
- `json` — structured output
- `csv` — spreadsheet, pipeline, or SIEM-friendly output

JSON reports use `schema_version: 1.0`. The report structure is documented in [`schemas/arpticuno-report.schema.json`](schemas/arpticuno-report.schema.json).

Probe failures remain visible in the summaries so timeouts or unreachable destinations are not reported as confirmed closed ports.

Top-level result states are:

- `completed`
- `partial`
- `inconclusive`
- `no-open-ports`
- `no-arp-responders`

## Demo

A synthetic preview is included and does not send network traffic:

```bash
python -m arpticuno.sandbox
```

## Scope and limits

Arpticuno is restricted to private or link-local IPv4 LAN targets and TCP connect scanning. The implementation includes bounds for target count, address scope, retries, discovered hosts, workers, timeouts, and total TCP probes.

ARP is unauthenticated. An observed reply does not prove device identity or ownership. If conflicting MAC addresses are observed for one IPv4 address, the MAC is reported as unknown.

See [SECURITY.md](SECURITY.md) for the security and trust-boundary notes.

## Project files

- `arpticuno/` — application code
- `assets/` — project logo
- `schemas/` — JSON report schema
- `pyproject.toml` — package and dependency configuration

## License

Arpticuno is released under the [MIT License](LICENSE).
