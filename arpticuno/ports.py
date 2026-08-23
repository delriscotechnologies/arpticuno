from __future__ import annotations

import errno
import math
import socket
from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from time import perf_counter

from arpticuno.discovery import validate_local_ipv4_host

MAX_PORT = 65_535
MAX_WORKERS = 512
MAX_TIMEOUT_SECONDS = 10.0
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


Probe = Callable[[str, int, float], PortResult]
ProgressCallback = Callable[[int, int], None]
ResultCallback = Callable[[PortResult], None]


def parse_ports(value: str) -> list[int]:
    """Parse comma-separated TCP ports and inclusive ranges."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Ports must be non-empty text")

    ports: set[int] = set()
    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            raise ValueError(f"Invalid port list: {value}")
        try:
            bounds = [int(item) for item in part.split("-")]
        except ValueError as exc:
            raise ValueError(f"Invalid port list: {value}") from exc
        if len(bounds) == 1:
            ports.add(_validate_port(bounds[0]))
        elif len(bounds) == 2:
            start, end = map(_validate_port, bounds)
            if start > end:
                raise ValueError("Port range start must be less than or equal to end")
            ports.update(range(start, end + 1))
        else:
            raise ValueError(f"Invalid port list: {value}")
    return sorted(ports)


def _validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError("Ports must be integers")
    if not 1 <= port <= MAX_PORT:
        raise ValueError(f"Ports must be between 1 and {MAX_PORT}")
    return port


def validate_scan_options(ports: Sequence[int], timeout: float, workers: int) -> list[int]:
    """Validate TCP controls and return de-duplicated ports."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout):
        raise ValueError("TCP connect timeout must be a finite number")
    if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"TCP connect timeout must be greater than 0 and no more than {MAX_TIMEOUT_SECONDS:g} seconds")
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"Workers must be an integer between 1 and {MAX_WORKERS}")
    if isinstance(ports, (str, bytes)):
        raise TypeError("Ports must be a sequence of integers")
    if len(ports) > MAX_PORT:
        raise ValueError(f"A scan cannot contain more than {MAX_PORT} TCP ports per host")

    validated = list(dict.fromkeys(_validate_port(port) for port in ports))
    return validated


def _result(host: str, port: int, state: str, start: float, error: str | None = None) -> PortResult:
    return PortResult(
        host=host,
        port=port,
        state=state,
        latency_ms=round((perf_counter() - start) * 1000, 2),
        error=error,
    )


def probe_connect(host: str, port: int, timeout: float = 0.75) -> PortResult:
    """Probe one TCP port with a kernel-managed connection attempt."""
    _validate_port(port)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("TCP connect timeout must be a positive finite number")

    start = perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return _result(host, port, "open", start)
    except TimeoutError:
        return _result(host, port, "timeout", start, "timeout")
    except OSError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if code in {errno.ECONNREFUSED, 10061}:
            return _result(host, port, "closed", start, "connection-refused")
        if code in {errno.ETIMEDOUT, 10060}:
            return _result(host, port, "timeout", start, "timeout")
        if code in {errno.EHOSTUNREACH, errno.ENETUNREACH, 10051, 10065}:
            return _result(host, port, "unreachable", start, str(code))
        return _result(host, port, "error", start, str(exc))


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
    """Scan many ports on one authorized LAN host."""
    return scan_ports_threaded(
        [host],
        ports,
        timeout=timeout,
        workers=workers,
        probe=probe,
        open_only=open_only,
        progress=progress,
        result_callback=result_callback,
    )


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
    """Scan all host/port pairs through one bounded worker pool."""
    if isinstance(hosts, (str, bytes)):
        raise TypeError("Hosts must be a sequence of IPv4 addresses")
    if len(hosts) > MAX_HOSTS_PER_SCAN:
        raise ValueError(f"A scan cannot contain more than {MAX_HOSTS_PER_SCAN} hosts")

    checked_hosts = list(dict.fromkeys(validate_local_ipv4_host(host) for host in hosts))
    checked_ports = validate_scan_options(ports, timeout, workers)
    total = len(checked_hosts) * len(checked_ports)
    if total > MAX_TOTAL_PROBES:
        raise ValueError(f"Scan would create {total:,} TCP probes; the safety limit is {MAX_TOTAL_PROBES:,}")
    if not total:
        return []

    jobs = iter(enumerate((host, port) for host in checked_hosts for port in checked_ports))
    results: list[tuple[int, PortResult]] = []
    completed = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending: dict[Future[PortResult], int] = {}

        def submit_next() -> bool:
            try:
                index, (host, port) = next(jobs)
            except StopIteration:
                return False
            pending[pool.submit(probe, host, port, timeout)] = index
            return True

        for _ in range(min(total, workers * MAX_PENDING_PER_WORKER)):
            submit_next()
        while pending:
            finished, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
            for future in finished:
                index = pending.pop(future)
                result = future.result()
                if not open_only or result.state == "open":
                    results.append((index, result))
                if result_callback:
                    result_callback(result)
                completed += 1
                if progress:
                    progress(completed, total)
                submit_next()

    return [result for _, result in sorted(results)]
