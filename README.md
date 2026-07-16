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

Arpticuno deliberately keeps network scanning small and understandable. Give it a local IPv4 target and it discovers live hosts with ARP, then checks the **first 7000 TCP ports** with normal socket connections.

It has one public command, reports only useful findings by default, and avoids advanced scanning or evasion features.

> Use Arpticuno only on systems and networks you own or have explicit permission to test.

## Quick Start

Arpticuno requires Python 3.10 or newer and a Linux environment with direct access to the LAN interface. On Ubuntu or WSL, install the base tools and the project:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip

git clone https://github.com/delriscotechnologies/arpticuno.git
cd arpticuno
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Run a scan:

```bash
sudo env "PATH=$PATH" arpticuno scan 192.168.1.0/24
```

The target can be a CIDR range, one IPv4 address, or a comma-separated mix:

```bash
sudo env "PATH=$PATH" arpticuno scan 192.168.1.10
sudo env "PATH=$PATH" arpticuno scan 192.168.1.10,192.168.1.20
sudo env "PATH=$PATH" arpticuno scan 192.168.1.0/24 --format json
sudo env "PATH=$PATH" arpticuno scan 192.168.1.0/24 --format csv
```

Some WSL2 network modes do not expose LAN ARP traffic in the same way as native Linux. If discovery returns no hosts unexpectedly, run Arpticuno from native Ubuntu or another Linux host connected directly to that LAN.

## What You Get

The default report answers the two questions that matter after a basic LAN scan: which hosts answered, and which TCP ports were open. Closed and timed-out ports do not flood the terminal.

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

Results:  Target(s): 192.168.1.0/24  │  Total active hosts: 3  │  Total open TCP ports: 5

Active hosts:
  Host 1
    IPv4: 192.168.1.1
    MAC: aa:bb:cc:dd:ee:01
    ARP RTT: 1.2 ms
    Open TCP Ports: 2
      Port: 53/tcp | State: open | Latency: 0.8 ms
      Port: 80/tcp | State: open | Latency: 0.9 ms

  Host 2
    IPv4: 192.168.1.10
    MAC: aa:bb:cc:dd:ee:10
    ARP RTT: 2.7 ms
    Open TCP Ports: 2
      Port: 22/tcp | State: open | Latency: 1.4 ms
      Port: 443/tcp | State: open | Latency: 1.8 ms

  Host 3
    IPv4: 192.168.1.25
    MAC: aa:bb:cc:dd:ee:25
    ARP RTT: 3.4 ms
    Open TCP Ports: 1
      Port: 3389/tcp | State: open | Latency: 2.1 ms
```

Choose the same findings in the format that fits the next step:

| Format | Best for |
| --- | --- |
| `table` | Reading results in the terminal |
| `json` | Scripts and structured tooling |
| `csv` | Spreadsheets, pipelines, and SIEM ingestion |

Preview the complete terminal experience with synthetic data and no network traffic:

```bash
python -m arpticuno.sandbox
```

## How It Works

A scan has three stages:

1. Validate that every requested target is a private or link-local IPv4 address.
2. Send ARP discovery on the local LAN and keep replies that belong to the requested target.
3. Run TCP connect checks against ports `1-7000` on each discovered host and report the open ports.

## Scope and Safeguards

Arpticuno is intentionally limited:

- IPv4 and local ARP discovery only
- private or link-local target ranges only
- TCP connect scanning only
- no more than 256 discovered hosts or 1,000,000 TCP probes per scan
- bounded target size, timeouts, retries, and worker counts
- out-of-scope ARP replies are discarded

It does not perform SYN or UDP scans, service fingerprinting, operating-system detection, banner grabbing, spoofing, evasion, or internet-wide scanning.

## Development

The locked development environment contains the test, lint, type, and security tools used by CI:

```bash
uv sync --locked --all-extras
uv run pytest -q
```

Every push and pull request also runs Ruff, mypy, Bandit, dependency auditing, and CodeQL. Security reports should follow [SECURITY.md](SECURITY.md).

## License

Arpticuno is available under the [MIT License](LICENSE).
