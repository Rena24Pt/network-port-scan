"""Tests for the scanning engine, using a throwaway local TCP server.

These tests bind a real socket on 127.0.0.1 so the scanner exercises the actual
network path (handshake + banner read) without touching any external host.
"""

import socket
import threading

import pytest

from portscanner.scanner import Scanner

_BANNER = b"TEST-SERVICE 1.0 ready\r\n"


@pytest.fixture
def tcp_server():
    """Yield the port of a local server that greets every client with a banner."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))  # port 0 => OS picks a free port
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        srv.settimeout(0.25)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                try:
                    conn.sendall(_BANNER)
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        # Signal the loop to stop and let it exit before closing the socket, so
        # we never yank the file descriptor out from under a blocked accept().
        stop.set()
        thread.join(timeout=1)
        srv.close()


def _find_closed_port() -> int:
    """Return a port number that is (almost certainly) not listening."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # closing frees the port, so a connect there should be refused
    return port


def test_open_port_is_detected_with_banner(tcp_server):
    scanner = Scanner("127.0.0.1", timeout=1.0, workers=5)
    result = scanner.scan_port(tcp_server)
    assert result.is_open
    assert "TEST-SERVICE" in result.banner


def test_closed_port_is_reported_closed():
    scanner = Scanner("127.0.0.1", timeout=0.5, workers=5)
    result = scanner.scan_port(_find_closed_port())
    assert not result.is_open
    assert result.banner == ""


def test_scan_results_are_sorted_by_port(tcp_server):
    scanner = Scanner("127.0.0.1", timeout=0.5, workers=10)
    results = scanner.scan([tcp_server, 1, 2, 3])
    ports = [r.port for r in results]
    assert ports == sorted(ports)


def test_unresolvable_host_raises():
    with pytest.raises(ValueError):
        Scanner("this-host-should-not-exist.invalid")
