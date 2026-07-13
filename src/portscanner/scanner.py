"""Core scanning engine: a TCP connect scan driven by a thread pool."""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from .banner import grab_banner, identify_service


@dataclass
class ScanResult:
    """The outcome of probing a single TCP port."""

    port: int
    is_open: bool
    service: str = ""
    banner: str = ""
    latency_ms: float = 0.0


@dataclass
class Scanner:
    """A multithreaded TCP *connect* scanner.

    A connect scan performs a full TCP three-way handshake using the operating
    system's socket API (:func:`socket.connect_ex`). If the handshake completes,
    the port is open; a refusal (TCP RST) or a timeout means it is closed or
    filtered. This is the most portable scan type because it needs no special
    privileges — unlike a SYN "half-open" scan, which crafts raw packets and
    therefore requires root/administrator rights.

    The scan is I/O-bound (most time is spent waiting on the network), so a
    thread pool gives a large speed-up despite Python's GIL: while one thread
    blocks on a socket, the GIL is released and others make progress.
    """

    target: str
    timeout: float = 1.0
    workers: int = 100
    grab_banners: bool = True
    _ip: str = field(init=False, default="")

    def __post_init__(self) -> None:
        # Resolve the hostname once, up front, so every worker reuses the same
        # IP and a bad hostname fails fast with a clear error.
        try:
            self._ip = socket.gethostbyname(self.target)
        except socket.gaierror as exc:
            raise ValueError(f"could not resolve host {self.target!r}: {exc}") from exc

    @property
    def ip(self) -> str:
        """The resolved IPv4 address of the target."""
        return self._ip

    def scan_port(self, port: int) -> ScanResult:
        """Probe a single TCP port and, if open, grab its banner."""
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            # connect_ex returns an error code (0 == success) instead of raising,
            # which is convenient for a scanner probing thousands of ports.
            connected = sock.connect_ex((self._ip, port)) == 0
            latency_ms = (time.perf_counter() - start) * 1000.0

            if not connected:
                return ScanResult(port, is_open=False, latency_ms=latency_ms)

            banner = ""
            if self.grab_banners:
                banner = grab_banner(sock, self.target, port, self.timeout)
            service = identify_service(port, banner)
            return ScanResult(port, True, service, banner, latency_ms)

    def scan(
        self,
        ports: Iterable[int],
        progress: Optional[Callable[[int, int], None]] = None,
    ) -> list[ScanResult]:
        """Scan many ports concurrently and return results sorted by port.

        :param ports: an iterable of port numbers to probe.
        :param progress: optional callback invoked as ``progress(done, total)``
            after each port completes — handy for a live progress indicator.
        """
        ports = list(ports)
        total = len(ports)
        if total == 0:
            return []

        # No point spawning more threads than there are ports to scan.
        workers = max(1, min(self.workers, total))
        results: list[ScanResult] = []

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in ports}
            for done, future in enumerate(as_completed(futures), start=1):
                results.append(future.result())
                if progress is not None:
                    progress(done, total)

        results.sort(key=lambda r: r.port)
        return results
