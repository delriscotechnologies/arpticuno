# Third-party notices

Arpticuno's own source code is licensed under the MIT License in `LICENSE`. Third-party packages retain their own copyright and license terms.

## Runtime dependency

### Scapy 2.7.0

- Purpose: ARP packet construction, transmission, and reply collection
- License: GNU General Public License version 2 only (`GPL-2.0-only`)
- Upstream project: `secdev/scapy`

The complete Scapy license text and corresponding source are available from the upstream project and the package distribution. This notice does not replace or modify Scapy's license terms.

## Development dependencies

The locked development environment also contains pytest, Ruff, mypy, Bandit, pip-audit, uv, and their transitive dependencies. These tools are used for testing, linting, type checking, security analysis, dependency auditing, and environment management; each retains its upstream license.

Redistributors should review the locked dependency set and include any notices or source offers required by the way they package or distribute Arpticuno and its dependencies.
