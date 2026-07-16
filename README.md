<p align="center">
  <img src="assets/arpticuno-logo.png" alt="Arpticuno logo" width="420">
</p>


Arpticuno is a small open-source IPv4 LAN scanner built to be easy to understand, easy to run, and hard to misuse by accident.

You give it a target. It finds live hosts on your local network with ARP. Then it checks the **first 7000 TCP ports** on each live host with normal Python socket connections.

It is not trying to be a full professional scanner. That is the point.

> Use Arpticuno only on systems and networks you own or have explicit permission to test.

## requirements for Ubuntu / WSL

Arpticuno runs best on a Linux environment where ARP packets can reach the local network directly.

You need:

- Python 3.10 or newer
- `pip` and `venv`
- permission to run ARP discovery with elevated privileges
- access to the local LAN interface you want to scan
- internet access the first time you install dependencies

Install the base tools on Ubuntu / WSL like this:

```
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

Then install Arpticuno:

```
cd arpticuno
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .[dev]
python -m pytest -q
```

If `sudo` drops your virtualenv path, use:

```
sudo env "PATH=$PATH" arpticuno scan 192.168.1.0/24
```

> Note: on some WSL2 setups, LAN ARP discovery may behave differently than on native Ubuntu because of the network model. If that happens, native Ubuntu is the safer choice for local-network discovery.

## one command

```
arpticuno scan <target>
```

That is the whole public CLI.

## what happens when you run it

When you run `arpticuno scan <target>`, Arpticuno:

1. validates the target
2. uses ARP to discover live IPv4 hosts on the local LAN
3. scans TCP ports `1-7000` on each live host
4. shows a clean summary with active hosts and open ports

## what `<target>` can be

You can pass:

- a CIDR range like `192.168.1.0/24`
- a single IPv4 host like `192.168.1.10`
- a comma-separated mix like `192.168.1.10,192.168.1.20,192.168.2.0/24`

## quick examples

```
sudo arpticuno scan 192.168.1.0/24
sudo arpticuno scan 192.168.1.10
sudo arpticuno scan 192.168.1.10,192.168.1.20
sudo arpticuno scan 192.168.1.0/24 --format json
sudo arpticuno scan 192.168.1.0/24 --format csv
```

## output formats

Arpticuno supports three output formats:

- `table` — normal human-readable terminal output
- `json` — structured output for scripts or tooling
- `csv` — flat rows for spreadsheets, pipelines, or SIEM ingestion

The default report stays focused on useful findings. It shows live hosts and open ports instead of dumping every closed or timed out port.

## sandbox preview

If you want to see the UI without touching a real network, run:

```bash
python -m arpticuno.sandbox
```

The table view opens with the Arpticuno wordmark, followed by the Del Risco Technologies block centered against the wordmark's fixed width. The results stay left-aligned so hosts and open ports remain easy to scan:

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

This preview uses fake LAN data and does not send packets. Addresses, latencies, and open ports will vary during a real scan.

The wordmark was generated with [TAAG](https://patorjk.com/software/taag/#p=display&f=Georgia11&t=Arpticuno) using the **Georgia11** font.

## scope

Arpticuno v1 stays narrow on purpose:

- IPv4 only
- ARP discovery for local private or link-local LAN ranges only
- TCP connect scanning only
- the **first 7000 TCP ports** by default
- reports focused on open ports
- bounded target scope, timeout, retry, and worker behavior to reduce accidental resource exhaustion
- ARP replies must belong to the requested target network
- no more than 256 discovered hosts or 1,000,000 TCP probes per scan

## what Arpticuno does not do

Arpticuno does not do:

- SYN scans
- UDP scans
- service fingerprinting
- OS detection
- banner grabbing
- spoofing
- evasion features
- internet-wide scanning

## why this project exists

Arpticuno is meant to be a clean first scanner project.

It shows that you understand:

- ARP discovery
- TCP connect scanning
- safe input validation
- clean CLI design
- structured reporting
- testing and basic AppSec thinking

## notes for real-world use

- ARP discovery needs the local network. This is a LAN tool, not a public internet scanner.
- Depending on your environment, you may need elevated privileges for ARP/scapy.
- In WSL or a virtual environment, `sudo` may drop your venv path. If that happens, use:

```
sudo env "PATH=$PATH" arpticuno scan 192.168.1.0/24
```

## current status

Arpticuno is intentionally simple right now.
The goal is to keep the command surface clean, the behavior understandable, and the output easy to read.

Testing, linting, type checking, bandit scanning, and dependency auditing are built into the project and run on every push and pull request. 

Security reports should follow [SECURITY.md](SECURITY.md).

