<p align="center">
  <img src="assets/arpticuno-logo.png" alt="Arpticuno" width="420">
</p>

<p align="center">
  A focused IPv4 LAN scanner for clear host discovery and TCP port results.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#command-options">Options</a> ·
  <a href="#output-and-automation">Output</a> ·
  <a href="#scope-and-safeguards">Scope</a> ·
  <a href="SECURITY.md">Security</a>
</p>

---

Arpticuno deliberately keeps network scanning small and understandable. Give it a private or link-local IPv4 LAN target and it records matching ARP replies, then checks selected TCP ports with normal socket connections. Without `--ports`, it scans the **first 7000 TCP ports**.

It has one public command, reports useful findings and probe-health summaries, and avoids advanced scanning or evasion features.

> Use Arpticuno only on systems and networks you own or have explicit permission to test.

## Quick Start

Arpticuno requires Python 3.10 or newer and direct access to the LAN interface. CI verifies Python 3.10 through 3.14 on Linux, runs portable smoke tests on Windows, and performs an isolated end-to-end ARP and TCP test with Linux network namespaces.

On Ubuntu or WSL, install the project:

```bash
git clone https://github.com/delriscotechnologies/arpticuno.git
cd arpticuno
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

The end-user installation path uses `pyproject.toml`; it does not read `uv.lock`. The runtime Scapy dependency is pinned exactly. To reproduce the repository's locked CI and development environment, install `uv` 0.11.29 and run:

```bash
uv sync --locked --all-extras
```

Raw ARP access may require elevated privileges. Use the virtual-environment executable by absolute path rather than passing a user-controlled `PATH` into `sudo`:

```bash
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.0/24
```

The default TCP selection remains ports `1-7000`. A single host, CIDR, or comma-separated target list is accepted:

```bash
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.10
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.10,192.168.1.20
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.0/24 --ports 22,80,443,8000-8100
```

Some WSL2 modes do not expose LAN ARP traffic like native Linux. If discovery unexpectedly returns no hosts, use native Linux connected directly to the LAN. Windows requires Npcap for actual ARP discovery; the Windows CI job validates portable CLI and TCP components but does not replace a real Npcap integration test.

## Command Options

```text
arpticuno scan <target>
  --iface <name>             ARP interface, such as eth0
  --arp-timeout <seconds>    ARP timeout, greater than 0 and at most 10
  --retries <count>          Additional ARP attempts, 0-5
  --ports <selection>        TCP ports and ranges; default 1-7000
  --connect-timeout <sec>    TCP connect timeout; default 0.2
  --workers <count>          TCP worker count, 1-512; default 256
  --format table|json|csv    Output format
  --output <path>            Write the report to a file
  --no-banner                Suppress terminal branding
  --fail-on-inconclusive     Return exit code 3 when every TCP probe fails
```

Examples:

```bash
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.0/24 --ports 22,80,443
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.0/24 --workers 64 --connect-timeout 0.5
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.0/24 --format json --output scan.json --no-banner
```

## Output and Automation

The table report answers which hosts sent matching ARP replies, which selected TCP ports were open, and whether timeouts or connection errors make a negative result inconclusive. Closed ports do not flood the terminal.

| Format | Best for |
| --- | --- |
| `table` | Reading findings and probe warnings in the terminal |
| `json` | Scripts and structured tooling |
| `csv` | Spreadsheets, pipelines, and SIEM ingestion |

JSON and CSV reports expose `schema_version: 1.0`. The machine-readable contract is documented in [`schemas/arpticuno-report.schema.json`](schemas/arpticuno-report.schema.json). CSV text cells that could be interpreted as spreadsheet formulas are neutralized, including values with leading whitespace or control characters.

Top-level report statuses are:

| Status | Meaning |
| --- | --- |
| `completed` | At least one open port and no failed probes |
| `partial` | Some probes failed, but the scan produced conclusive results |
| `inconclusive` | Every TCP probe timed out, was unreachable, or failed |
| `no-open-ports` | All selected probes completed without an open port |
| `no-arp-responders` | No matching ARP reply was observed |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Command completed |
| `1` | Runtime, OS, privilege, Scapy, or output-file error |
| `2` | Invalid target or option |
| `3` | Inconclusive TCP result when `--fail-on-inconclusive` is enabled |

Preview the complete terminal experience with synthetic data and no network traffic:

```bash
python -m arpticuno.sandbox
```

## How It Works

A scan has three stages:

1. Validate every target as private or link-local IPv4 and collapse duplicate or overlapping entries.
2. Send ARP discovery on the selected local interface and retain only well-formed replies belonging to the requested scope. ARP is unauthenticated and does not prove device identity.
3. Run bounded TCP connect checks against the selected ports and report open ports plus aggregate outcomes.

The test suite covers validation, malformed and conflicting ARP observations, bounded work submission, TCP probing against a local socket, reporting, CSV safety, CLI behavior, package/version consistency, and output-schema consistency. CI additionally builds and imports the wheel, exercises portable components on Windows, and runs an authorized end-to-end scan inside isolated Linux network namespaces.

## Scope and Safeguards

Arpticuno is intentionally limited:

- IPv4 and local ARP discovery only
- private or link-local targets only in the CLI and batch scan APIs
- TCP connect scanning only
- at most 256 raw target entries, 65,536 unique target addresses, and 512 total ARP request rounds
- up to 256 ARP responders and 1,000,000 total TCP probes
- bounded timeouts, retries, worker counts, and queued tasks
- malformed and out-of-scope ARP replies are discarded
- conflicting MAC addresses for one IPv4 address are reported as `unknown`
- timeout, unreachable, and error counts remain visible so inconclusive scans are not reported as clean negatives
- strict integer validation for ports and worker counts

`probe_connect()` is a low-level single-socket helper and does not enforce authorization or local-network scope. The public CLI, `arp_discover()`, `scan_tcp_ports()`, and `scan_ports_threaded()` enforce their documented safety limits.

Arpticuno does not perform SYN or UDP scans, service fingerprinting, operating-system detection, banner grabbing, spoofing, evasion, exploitation, or internet-wide scanning.

See [SECURITY.md](SECURITY.md) for the trust boundary and vulnerability-reporting process.

## Development and Releases

Contribution instructions are in [CONTRIBUTING.md](CONTRIBUTING.md). User-visible changes are recorded in [CHANGELOG.md](CHANGELOG.md).

Tags formatted as `v<package-version>` run the complete validation set, build wheel and source distributions, generate a CycloneDX SBOM, and create a GitHub Release. The tag must exactly match `arpticuno.__version__`.

## License

Arpticuno source code is available under the [MIT License](LICENSE). Runtime and development dependencies retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
