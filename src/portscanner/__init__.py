"""portscanner — a fast, multithreaded TCP port scanner with banner grabbing.

This package is an educational, portfolio-grade implementation that demonstrates
core network-programming concepts:

* **Sockets** — the BSD socket API exposed by Python's :mod:`socket` module.
* **TCP/IP** — a "connect scan" completes the TCP three-way handshake to decide
  whether a port is open.
* **Banner grabbing** — reading what a service says on connect to identify it.
* **Concurrency** — a thread pool scans many ports at once for speed.

The public API is intentionally tiny: build a :class:`Scanner` and call
:meth:`Scanner.scan`.
"""

from .scanner import ScanResult, Scanner

__version__ = "0.1.0"
__all__ = ["Scanner", "ScanResult", "__version__"]
