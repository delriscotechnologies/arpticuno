from __future__ import annotations

import errno
import math
import socket
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from time import perf_counter
from typing import Callable, Sequence

from arpticuno.discovery import validate_local_ipv4_host

MAX_WORKERS = 512
MAX_TIMEOUT_SECONDS = 10.0
MAX_PORTS_PER_HOST = 65_535
MAX_HOSTS_PER_SCAN = 256
MAX_TOTAL_PROBES = 1_000_000
MAX_PENDING_PER_WORKER = 2


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    state: str
    proto: str = "tcp"
    latency_ms: float | None = None
    error: str | None = None


def parse_ports(value: str) -> list[int]:
    """Parse a comma-separated TCP port selection with optional ranges."""
    if not isinstance(value, str):
        raise ValueError("Ports must be provided as text")
    value = value.strip()
    if not value:
        raise ValueError("Ports cannot be empty")

    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"Invalid port list: {value}")
        try:
            if "-" in part:
                if part.count("-") != 1:
                    raise ValueError
                start_text, end_text = part.split("-", 1)
                start = int(start_text)
                end = int(end_text)
                if start > end:
                    raise ValueError("Port range start must be less than or equal to end")
                _validate_port(start)
                _validate_port(end)
                ports.extend(range(start, end + 1))
            else:
                port = int(part)
                _validate_port(port)
                ports.append(port)
        except ValueError as exc:
            if str(exc).startswith("Port"):
                raise
            raise ValueError(f"Invalid port list: {value}") from exc
    return sorted(set(ports))


def _validate_port(port: int) -> None:
    if isinstance(port, bool) or not isinstance(port, int):
        raise ValueError("Ports must be integers")
    if port < 1 or port > 65535:
        raise ValueError("Ports must be between 1 and 65535")


def _validate_scan_options(ports: Sequence[int], timeout: float, workers: int) -> list[int]:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout):
        raise ValueError("TCP connect timeout must be a finite number")
    if timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"TCP connect timeout must be greater than 0 and no more than {MAX_TIMEOUT_SECONDS:g} seconds"
        )
    if isinstance(workers, bool) or not isinstance(workers, int):
        raise ValueError("Workers must be an integer")
    if workers < 1 or workers > MAX_WORKERS:
        raise ValueError(f"Workers must be between 1 and {MAX_WORKERS}")
    if isinstance(ports, (str, bytes)):
        raise ValueError("Ports must be a sequence of integers")
    if len(ports) > MAX_PORTS_PER_HOST:
        raise ValueError(f"A scan cannot contain more than {MAX_PORTS_PER_HOST} TCP ports per host")

    validated_ports = list(dict.fromkeys(ports))
    for port in validated_ports:
        _validate_port(port)
    return validated_ports


def _latency_ms(start: float) -> float:
    return round((perf_counter() - start) * 1000.0, 2)


def probe_connect(host: str, port: int, timeout: float = 0.75) -> PortResult:
    """Probe one TCP port using a normal kernel-managed TCP connect attempt."""
    _validate_port(port)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("TCP connect timeout must be a positive finite number")

    start = perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return PortResult(host=host, port=port, state="open", latency_ms=_latency_ms(start))
    except ConnectionRefusedError:
        return PortResult(
            host=host,
            port=port,
            state="closed",
            latency_ms=_latency_ms(start),
            error="connection-refused",
        )
    except socket.timeout:
        return PortResult(
            host=host,
            port=port,
            state="timeout",
            latency_ms=_latency_ms(start),
            error="timeout",
        )
    except OSError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if code in {errno.ECONNREFUSED, 10061}:
            state, error = "closed", "connection-refused"
        elif code in {errno.ETIMEDOUT, 10060}:
            state, error = "timeout", "timeout"
        elif code in {errno.EHOSTUNREACH, errno.ENETUNREACH, 10051, 10065}:
            state, error = "unreachable", str(code)
        else:
            state, error = "error", str(exc)
        return PortResult(
            host=host,
            port=port,
            state=state,
            latency_ms=_latency_ms(start),
            error=error,
        )


Probe = Callable[[str, int, float], PortResult]
ProgressCallback = Callable[[int, int], None]
ResultCallback = Callable[[PortResult], None]


def scan_tcp_ports(
    host: str,
    ports: Sequence[int],
    timeout: float = 0.2,
    probe: Probe = probe_connect,
    workers: int = 256,
    open_only: bool = False,
    progress: ProgressCallback | None = None,
    result_callback: ResultCallback | None = None,
) -> list[PortResult]:
    """Scan many ports on one authorized LAN host with bounded concurrency."""
    validated_host = validate_local_ipv4_host(host)
    validated_ports = _validate_scan_options(ports, timeout, workers)
    if not validated_ports:
        return []

    results_by_index: list[PortResult | None] = [None] * len(validated_ports)
    completed = 0
    indexed_ports = iter(enumerate(validated_ports))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending: dict[Future[PortResult], int] = {}

        def submit_next() -> bool:
            try:
                index, port = next(indexed_ports)
            except StopIteration:
                return False
            pending[pool.submit(probe, validated_host, port, timeout)] = index
            return True

        for _ in range(min(len(validated_ports), workers * MAX_PENDING_PER_WORKER)):
            submit_next()

        while pending:
            completed_futures, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
            for future in completed_futures:
                index = pending.pop(future)
                result = future.result()
                results_by_index[index] = result
                completed += 1
                if result_callback is not None:
                    result_callback(result)
                if progress is not None:
                    progress(completed, len(validated_ports))
                submit_next()

    results = [result for result in results_by_index if result is not None]
    return [result for result in results if result.state == "open"] if open_only else results


def scan_ports_threaded(
    hosts: Sequence[str],
    ports: Sequence[int],
    timeout: float = 0.75,
    workers: int = 64,
    probe: Probe = probe_connect,
    open_only: bool = False,
    progress: ProgressCallback | None = None,
    result_callback: ResultCallback | None = None,
) -> list[PortResult]:
    """Scan multiple authorized LAN hosts with the shared bounded port engine."""
    if isinstance(hosts, (str, bytes)):
        raise ValueError("Hosts must be a sequence of IPv4 addresses")
    if len(hosts) > MAX_HOSTS_PER_SCAN:
        raise ValueError(f"A scan cannot contain more than {MAX_HOSTS_PER_SCAN} discovered hosts")

    validated_hosts = list(dict.fromkeys(validate_local_ipv4_host(host) for host in hosts))
    validated_ports = _validate_scan_options(ports, timeout, workers)
    total_steps = len(validated_hosts) * len(validated_ports)
    if total_steps > MAX_TOTAL_PROBES:
        raise ValueError(
            f"Scan would create {total_steps:,} TCP probes; the safety limit is {MAX_TOTAL_PROBES:,}. "
            "Use a narrower target scope."
        )

    results: list[PortResult] = []
    completed_steps = 0
    for host in validated_hosts:
        previous_done_for_host = 0

        def host_progress(done_for_host: int, total_for_host: int) -> None:
            nonlocal completed_steps, previous_done_for_host
            completed_steps += done_for_host - previous_done_for_host
            previous_done_for_host = done_for_host
            if progress is not None:
                progress(completed_steps, total_steps)

        results.extend(
            scan_tcp_ports(
                host,
                validated_ports,
                timeout=timeout,
                probe=probe,
                workers=workers,
                open_only=open_only,
                progress=host_progress if total_steps else None,
                result_callback=result_callback,
            )
        )
    return results
