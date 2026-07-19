<p align="center">
  <img src="assets/arpticuno-logo.png" alt="Arpticuno" width="420">
</p>

<p align="center">
  A focused IPv4 LAN scanner for clear host discovery and TCP port results.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#what-you-get">Output</a> ·
  <a href="#scope-and-safeguards">Scope</a> ·
  <a href="SECURITY.md">Security</a>
</p>

---

Arpticuno deliberately keeps network scanning small and understandable. Give it a local IPv4 target and it records matching ARP replies, then checks the **first 7000 TCP ports** with normal socket connections.

It has one public command, reports useful findings and probe-health summaries, and avoids advanced scanning or evasion features.

> Use Arpticuno only on systems and networks you own or have explicit permission to test.

## Quick Start

Arpticuno requires Python 3.10 or newer and direct access to the LAN interface. CI tests Python 3.10 through 3.14. Linux is the documented installation path below; Windows can also run Scapy with Npcap installed. On Ubuntu or WSL, install the base tools and the project:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip

git clone https://github.com/delriscotechnologies/arpticuno.git
cd arpticuno
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Run a scan with the virtual environment executable by absolute path. This avoids passing a user-controlled `PATH` into a privileged process:

```bash
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.0/24
```

The target can be a CIDR range, one IPv4 address, or a comma-separated mix:

```bash
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.10
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.10,192.168.1.20
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.0/24 --format json
sudo "$(pwd)/.venv/bin/arpticuno" scan 192.168.1.0/24 --format csv
```

Some WSL2 network modes do not expose LAN ARP traffic in the same way as native Linux. If discovery returns no hosts unexpectedly, run Arpticuno from native Ubuntu or another Linux host connected directly to that LAN.

## What You Get

The default report answers three questions after a basic LAN scan: which hosts sent matching ARP replies, which TCP ports were open, and whether timeouts or connection errors make a negative result inconclusive. Closed ports do not flood the terminal.

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

Choose the same findings in the format that fits the next step:

| Format | Best for |
| --- | --- |
| `table` | Reading results and probe warnings in the terminal |
| `json` | Scripts and structured tooling |
| `csv` | Spreadsheets, pipelines, and SIEM ingestion; even zero-host scans contain an auditable summary row |

CSV text fields that could be interpreted as spreadsheet formulas are neutralized before output.

Preview the complete terminal experience with synthetic data and no network traffic:

```bash
python -m arpticuno.sandbox
```

## How It Works

A scan has three stages:

1. Validate that every requested target is a private or link-local IPv4 address.
2. Send ARP discovery on the local LAN and retain well-formed replies that belong to the requested target. ARP is unauthenticated and does not prove device identity.
3. Run bounded TCP connect checks against ports `1-7000` on each discovered host and report open ports plus aggregate outcomes.

Automated checks cover target validation, malformed and conflicting ARP observations, TCP probing against a local test socket, bounded scan behavior, reporting, CSV safety, and safety limits. They do not reproduce a physical LAN end to end, so discovery should be verified on an authorized test segment before the results are relied upon.

## Scope and Safeguards

Arpticuno is intentionally limited:

- IPv4 and local ARP discovery only
- private or link-local target ranges only in the CLI and batch scan APIs
- TCP connect scanning only
- up to 256 ARP responders, with a separate 1,000,000-probe limit; at the default 7,000-port range, TCP scanning is limited to 142 hosts
- bounded target size, timeouts, retries, worker counts, and queued TCP tasks
- out-of-scope and malformed ARP replies are discarded
- conflicting MAC addresses observed for one IPv4 address are reported as `unknown`
- timeouts, unreachable results, and errors are retained as summaries so an inconclusive scan is not presented as a clean negative

`probe_connect()` is a low-level single-socket helper and does not enforce authorization or local-network scope. The public CLI, `scan_tcp_ports()`, and `scan_ports_threaded()` enforce private/link-local IPv4 targets.

It does not perform SYN or UDP scans, service fingerprinting, operating-system detection, banner grabbing, spoofing, evasion, or internet-wide scanning.

See [SECURITY.md](SECURITY.md) for reporting and handling guidance.

## License

Arpticuno source code is available under the [MIT License](LICENSE). Runtime and development dependencies retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
