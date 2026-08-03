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

Arpticuno officially supports Linux with Python 3.10 or newer and direct access to the LAN interface. CI verifies Python 3.10 through 3.14 on Linux and performs an isolated end-to-end ARP and TCP test with Linux network namespaces. Windows can run the portable CLI, TCP scanning, and reporting components, but actual ARP discovery requires Npcap and is not currently covered by automated integration tests. Windows support is therefore best effort.

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

Some WSL2 modes do not expose LAN ARP traffic like native Linux. If discovery unexpectedly returns no hosts, use native Linux connected directly to the LAN.

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

The example below is generated from the repository's synthetic sandbox data. It demonstrates the exact output format without claiming that these hosts came from a real LAN.

```text
      db                           mm     db
     ;MM:                          MM
    ,V^MM.    `7Mb,od8 `7MMpdMAo.mmMMmm `7MM  ,p6"bo `7MM  `7MM  `7MMpMMMb.  ,pW"Wq.
   ,M  `MM      MM' "'   MM   `Wb  MM     MM 6M'  OO   MM    MM    MM    MM 6W'   `Wb
   AbmmmqMA     MM       MM    M8  MM     MM 8M        MM    MM    MM    MM 8M     M8
  A'     VML    MM       MM   ,AP  MM     MM YM.    ,  MM    MM    MM    MM YA.   ,A9
.AMA.   .AMMA..JMML.     MMbmmd'   `Mbmo.JMML.YMbmd'   `Mbod"YML..JMML  JMML.`Ybmd9'
                         MM
                       .JMML.

                             ╔══════════════════════════╗
                             ║  Del Risco Technologies  ║
                             ╚══════════════════════════╝

Results:  Target(s): 192.168.1.0/24  │  Total ARP responders: 3  │  Total TCP probes: 21000  │  Total open TCP ports: 5
Status: completed

ARP responders:
  Host 1
    IPv4: 192.168.1.1
    MAC: aa:bb:cc:dd:ee:01
    ARP RTT: 1.2 ms
    TCP Probes: 7000
    Open TCP Ports: 2
      Port: 53/tcp | State: open | Latency: 0.8 ms
      Port: 80/tcp | State: open | Latency: 0.9 ms

  Host 2
    IPv4: 192.168.1.10
    MAC: aa:bb:cc:dd:ee:10
    ARP RTT: 2.7 ms
    TCP Probes: 7000
    Open TCP Ports: 2
      Port: 22/tcp | State: open | Latency: 1.4 ms
      Port: 443/tcp | State: open | Latency: 1.8 ms

  Host 3
    IPv4: 192.168.1.25
    MAC: aa:bb:cc:dd:ee:25
    ARP RTT: 3.4 ms
    TCP Probes: 7000
    Open TCP Ports: 1
      Port: 3389/tcp | State: open | Latency: 2.1 ms
```

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

The test suite covers validation, malformed and conflicting ARP observations, bounded work submission, TCP probing against a local socket, reporting, CSV safety, CLI behavior, package/version consistency, and output-schema consistency. CI additionally builds and imports the wheel, exercises portable components on Windows, runs an authorized end-to-end scan inside isolated Linux network namespaces, and enforces at least 80% package line coverage.

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

## Releases

User-visible changes are recorded in [CHANGELOG.md](CHANGELOG.md).

Tags formatted as `v<package-version>` run the complete validation set, enforce the same 80% line-coverage baseline as CI, build wheel and source distributions, generate a CycloneDX SBOM, and create a GitHub Release. The tag must exactly match `arpticuno.__version__`.

## License

Arpticuno source code is available under the [MIT License](LICENSE).

Runtime and development dependencies retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
