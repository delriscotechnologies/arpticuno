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
uv run --no-sync ruff check arpticuno tests tools
uv run --no-sync mypy arpticuno tools
uv run --no-sync bandit -q -r arpticuno tools
uv run --no-sync pip-audit --local --skip-editable
uv run --no-sync python -m trace \
  --count --missing --coverdir .tracecov \
  --ignore-dir "$(pwd)/.venv" \
  --module pytest -q
uv run --no-sync python tools/check_coverage.py .tracecov arpticuno 80
uv build --no-sources
```

CI and releases require at least 80% line coverage for the `arpticuno` package. The gate uses Python's standard-library tracer and does not add another dependency to the locked environment.

## Scope expectations

Changes must not add internet-wide scanning, evasion, spoofing, credential collection, exploitation, destructive behavior, or functionality that bypasses the documented private/link-local target restrictions.

Network tests must use systems and networks you own or are explicitly authorized to test. Prefer synthetic data, loopback sockets, or isolated network namespaces.

## Pull requests

Keep each pull request limited to one coherent change. Include what changed, why it changed, user impact, security implications, and the commands used for validation. Update tests, README, security guidance, schema, and changelog when the public behavior changes.

Do not include credentials, private network details, packet captures containing unrelated traffic, or working exploit material.
