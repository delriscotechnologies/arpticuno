from __future__ import annotations

import errno
import math
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from time import perf_counter
from typing import Callable, Sequence

ALL_TCP_PORTS = tuple(range(1, 65536))
MAX_WORKERS = 512
MAX_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    state: str
    proto: str = "tcp"
    latency_ms: float | None = None
    error: str | None = None


def parse_ports(value: str) -> list[int]:
    """Parse explicit TCP port lists for compatibility helpers and tests."""
    value = value.strip()
    if not value:
        raise ValueError("Ports cannot be empty")

    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"Invalid port list: {value}")
        if "-" in part:
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

    return sorted(set(ports))


def _validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError("Ports must be between 1 and 65535")


def _validate_scan_options(ports: Sequence[int], timeout: float, workers: int) -> list[int]:
    if not math.isfinite(timeout) or timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
        raise ValueError(f"TCP connect timeout must be greater than 0 and no more than {MAX_TIMEOUT_SECONDS:g} seconds")
    if workers < 1 or workers > MAX_WORKERS:
        raise ValueError(f"Workers must be between 1 and {MAX_WORKERS}")
    validated_ports = list(ports)
    for port in validated_ports:
        _validate_port(port)
    return validated_ports


def _latency_ms(start: float) -> float:
    return round((perf_counter() - start) * 1000.0, 2)


def probe_connect(host: str, port: int, timeout: float = 0.75) -> PortResult:
    """Probe one TCP port using a normal kernel-managed TCP connect attempt."""
    start = perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return PortResult(host=host, port=port, proto="tcp", state="open", latency_ms=_latency_ms(start), error=None)
    except ConnectionRefusedError:
        return PortResult(host=host, port=port, proto="tcp", state="closed", latency_ms=_latency_ms(start), error="connection-refused")
    except socket.timeout:
        return PortResult(host=host, port=port, proto="tcp", state="timeout", latency_ms=_latency_ms(start), error="timeout")
    except OSError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if code in {errno.ECONNREFUSED, 10061}:
            return PortResult(host=host, port=port, proto="tcp", state="closed", latency_ms=_latency_ms(start), error="connection-refused")
        if code in {errno.ETIMEDOUT, 10060}:
            return PortResult(host=host, port=port, proto="tcp", state="timeout", latency_ms=_latency_ms(start), error="timeout")
        if code in {errno.EHOSTUNREACH, errno.ENETUNREACH, 10051, 10065}:
            return PortResult(host=host, port=port, proto="tcp", state="unreachable", latency_ms=_latency_ms(start), error=str(code))
        return PortResult(host=host, port=port, proto="tcp", state="error", latency_ms=_latency_ms(start), error=str(exc))


Probe = Callable[[str, int, float], PortResult]
ProgressCallback = Callable[[int, int], None]


def scan_tcp_ports(
    host: str,
    ports: Sequence[int],
    timeout: float = 0.2,
    probe: Probe = probe_connect,
    workers: int = 256,
    open_only: bool = False,
    progress: ProgressCallback | None = None,
) -> list[PortResult]:
    """Scan many ports on one host using a thread pool."""
    validated_ports = _validate_scan_options(ports, timeout, workers)
    if not validated_ports:
        return []

    results_by_index: list[PortResult | None] = [None] * len(validated_ports)
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(probe, host, port, timeout): index for index, port in enumerate(validated_ports)
        }
        for future in as_completed(future_map):
            index = future_map[future]
            results_by_index[index] = future.result()
            completed += 1
            if progress is not None:
                progress(completed, len(validated_ports))

    results = [result for result in results_by_index if result is not None]
    if open_only:
        return [result for result in results if result.state == "open"]
    return results


def scan_ports_threaded(
    hosts: Sequence[str],
    ports: Sequence[int],
    timeout: float = 0.75,
    workers: int = 64,
    probe: Probe = probe_connect,
    open_only: bool = False,
    progress: ProgressCallback | None = None,
) -> list[PortResult]:
    """Scan multiple hosts by scanning each host with the shared port engine."""
    results: list[PortResult] = []
    validated_ports = list(ports)
    total_steps = len(hosts) * len(validated_ports)
    completed_steps = 0

    for host in hosts:
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
            )
        )
    return results


# Backwards-compatible alias for older callers/tests.
scan_tcp_port = probe_connect
