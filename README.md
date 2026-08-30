<p align="center">
  <img src="assets/arpticuno-logo.jpg" alt="Arpticuno" width="420">
</p>

<p align="center">
  Focused IPv4 LAN discovery and TCP connect scanning for authorized environments.
</p>

---

Arpticuno is a small Windows Python CLI for discovering IPv4 hosts on a local private or link-local network and reporting selected TCP connectivity results. It is intentionally limited in scope and does not include advanced scanning, fingerprinting, exploitation, or evasion features.

> Use Arpticuno only on systems and networks you own or have explicit permission to test.

## Install

You need Windows and Python 3.10 or newer. Arpticuno uses the Windows IP Helper API directly, so Scapy, Npcap, and Administrator privileges are not required.

Clone the repository, create a virtual environment, and install the command:

```powershell
git clone https://github.com/delriscotechnologies/arpticuno.git
cd arpticuno
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
```

Run an authorized scan:

```powershell
arpticuno scan 192.168.1.0/24 --ports 22,80,443
```

## What it does

Arpticuno:

1. Validates private or link-local IPv4 targets.
2. Uses Windows `SendARP` calls in parallel to resolve responding IPv4 addresses and MAC addresses.
3. Checks selected TCP ports with normal socket connections.
4. Produces table, JSON, or CSV output.

The default TCP selection is ports `1-7000`. The CLI also supports custom port selections, worker counts, connection timeouts, output files, and banner suppression. `--iface` accepts a local source IPv4 address when Windows should use a specific interface. With `--fail-on-inconclusive`, the command returns exit code `3` when every TCP probe fails.

## Output

Supported formats:

- `table` — terminal-friendly results
- `json` — structured output
- `csv` — spreadsheet, pipeline, or SIEM-friendly output

JSON reports use `schema_version: 1.0`.

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

Arpticuno is restricted to Windows, private or link-local IPv4 targets on a directly connected LAN, and TCP connect scanning. Windows `SendARP` resolves physical addresses only for destinations on the local subnet.

The implementation enforces these safety limits:

| Limit | Maximum |
| --- | ---: |
| Comma-separated target entries | 256 |
| Distinct ARP target addresses | 65,536 |
| ARP requests, including retries | 65,536 |
| ARP retries | 5 |
| Discovered hosts | 256 |
| TCP ports per host | 65,535 |
| Concurrent TCP workers | 512 |
| ARP or TCP timeout | 10 seconds |
| Total TCP probes | 1,000,000 |

ARP requests are calculated as `target addresses × (retries + 1)`. A target that fits the address limit can therefore exceed the request limit when retries are enabled.

ARP is unauthenticated. An observed reply does not prove device identity or ownership. If conflicting MAC addresses are observed for one IPv4 address, the MAC is reported as unknown.

The Windows API controls the timeout of each native ARP request. The `--arp-timeout` value is retained for report-schema and command-line compatibility but cannot override that operating-system timeout. Reported ARP RTT is the elapsed `SendARP` call time and may reflect a cached neighbor-table result.

See [SECURITY.md](SECURITY.md) for the security and trust-boundary notes.

## License

Arpticuno is released under the [MIT License](LICENSE).
