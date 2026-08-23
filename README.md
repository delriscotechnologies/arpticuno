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

JSON reports use `schema_version: 1.0`.

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

Example table output:

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

                             +--------------------------+
                             |  Del Risco Technologies  |
                             +--------------------------+

Results: Target(s): 192.168.1.0/24 | ARP responders: 3 | TCP probes: 21000 | Open TCP ports: 5
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

## Scope and limits

Arpticuno is restricted to private or link-local IPv4 LAN targets and TCP connect scanning. The implementation includes bounds for target count, address scope, retries, discovered hosts, workers, timeouts, and total TCP probes.

ARP is unauthenticated. An observed reply does not prove device identity or ownership. If conflicting MAC addresses are observed for one IPv4 address, the MAC is reported as unknown.

See [SECURITY.md](SECURITY.md) for the security and trust-boundary notes.

## License

Arpticuno is released under the [MIT License](LICENSE).
