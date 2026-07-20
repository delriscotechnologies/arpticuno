# Contributing

Arpticuno accepts focused fixes and improvements that preserve its intentionally narrow, authorized-LAN scope.

## Development setup

Install the exact tool and dependency versions used by CI:

```bash
uv sync --locked --all-extras
```

Run the complete validation set before submitting changes:

```bash
uv run --no-sync pytest -q
uv run --no-sync ruff check arpticuno tests
uv run --no-sync mypy arpticuno
uv run --no-sync bandit -q -r arpticuno
uv run --no-sync pip-audit --local --skip-editable
uv build --no-sources
```

## Scope expectations

Changes must not add internet-wide scanning, evasion, spoofing, credential collection, exploitation, destructive behavior, or functionality that bypasses the documented private/link-local target restrictions.

Network tests must use systems and networks you own or are explicitly authorized to test. Prefer synthetic data, loopback sockets, or isolated network namespaces.

## Pull requests

Keep each pull request limited to one coherent change. Include what changed, why it changed, user impact, security implications, and the commands used for validation. Update tests, README, security guidance, schema, and changelog when the public behavior changes.

Do not include credentials, private network details, packet captures containing unrelated traffic, or working exploit material.
